//! gg-engine: multithreaded functional-similarity search for graphify-ghidra.
//!
//! Implements the specification in `similarity.py` exactly (FNV-1a shingles, 64-slot
//! MinHash via splitmix64, 16x4 band LSH, exact-Jaccard re-rank, weighted composite,
//! top-k of either endpoint). The Python module is the reference; the two are
//! compared in the test suite.
//!
//!     gg-engine similar --in records.jsonl --out edges.json
//!         [--threshold 0.72] [--top-k 5] [--min-instrs 10] [--query-scope S] [--threads N]

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

const NUM_PERM: usize = 64;
const BANDS: usize = 16;
const ROWS: usize = 4;
const SHINGLE_K: usize = 4;
const BUCKET_CAP: usize = 64;
// Order matters: Python sums in this order, and float addition is not associative.
const W_MN: f64 = 0.45;
const W_EXPR: f64 = 0.25;
const W_API: f64 = 0.15;
const W_CONST: f64 = 0.10;
const W_STR: f64 = 0.05;

#[derive(Deserialize)]
struct Rec {
    id: String,
    scope: String,
    #[serde(default)]
    mn: String,
    #[serde(default)]
    consts: Vec<String>,
    #[serde(default)]
    apis: Vec<String>,
    #[serde(default)]
    strs: Vec<String>,
    #[serde(default)]
    instrs: u32,
    #[serde(default)]
    expr: Vec<u64>,
}

#[derive(Serialize)]
struct Edge {
    a: String,
    b: String,
    score: f64,
    mn: Option<f64>,
    expr: Option<f64>,
    api: Option<f64>,
    #[serde(rename = "const")]
    konst: Option<f64>,
    #[serde(rename = "str")]
    strs: Option<f64>,
}

struct Prepared {
    shingles: Vec<u64>,
    sig: [u64; NUM_PERM],
    apis: Vec<String>,
    consts: Vec<String>,
    strs: Vec<String>,
    expr: Vec<u64>,
}

#[inline]
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn shingle_hashes(mn: &str) -> Vec<u64> {
    let toks: Vec<&str> = mn.split_whitespace().collect();
    if toks.is_empty() {
        return Vec::new();
    }
    let mut hs: Vec<u64> = if toks.len() < SHINGLE_K {
        vec![fnv1a64(toks.join(" ").as_bytes())]
    } else {
        toks.windows(SHINGLE_K).map(|w| fnv1a64(w.join(" ").as_bytes())).collect()
    };
    hs.sort_unstable();
    hs.dedup();
    hs
}

fn minhash(sh: &[u64], seeds: &[u64; NUM_PERM]) -> [u64; NUM_PERM] {
    let mut sig = [u64::MAX; NUM_PERM];
    for &h in sh {
        for i in 0..NUM_PERM {
            let v = mix(h ^ seeds[i]);
            if v < sig[i] {
                sig[i] = v;
            }
        }
    }
    sig
}

fn band_key(sig: &[u64; NUM_PERM], b: usize) -> u64 {
    let mut acc = (b + 1) as u64;
    for r in 0..ROWS {
        acc = mix(acc ^ sig[b * ROWS + r]);
    }
    acc
}

fn sorted_unique<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Exact Jaccard of two sorted, deduplicated slices.
fn jaccard<T: Ord>(a: &[T], b: &[T]) -> Option<f64> {
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let (mut i, mut j, mut inter) = (0usize, 0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    Some(inter as f64 / (a.len() + b.len() - inter) as f64)
}

fn add_bucket_pairs(members: &mut Vec<u32>, out: &mut Vec<(u32, u32)>) {
    if members.len() < 2 || members.len() > BUCKET_CAP {
        return;
    }
    members.sort_unstable();
    for x in 0..members.len() {
        for y in (x + 1)..members.len() {
            out.push((members[x], members[y]));
        }
    }
}

fn round4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}

struct Args {
    input: String,
    output: String,
    threshold: f64,
    top_k: usize,
    min_instrs: u32,
    query_scope: Option<String>,
    threads: Option<usize>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) != Some("similar") {
        return Err("usage: gg-engine similar --in FILE --out FILE [--threshold F] [--top-k N] [--min-instrs N] [--query-scope S] [--threads N]".into());
    }
    let mut a = Args { input: String::new(), output: String::new(), threshold: 0.72, top_k: 5, min_instrs: 10, query_scope: None, threads: None };
    let mut i = 1;
    while i < argv.len() {
        let key = argv[i].as_str();
        let val = argv.get(i + 1).ok_or_else(|| format!("{key} needs a value"))?;
        match key {
            "--in" => a.input = val.clone(),
            "--out" => a.output = val.clone(),
            "--threshold" => a.threshold = val.parse().map_err(|_| "bad --threshold")?,
            "--top-k" => a.top_k = val.parse().map_err(|_| "bad --top-k")?,
            "--min-instrs" => a.min_instrs = val.parse().map_err(|_| "bad --min-instrs")?,
            "--query-scope" => a.query_scope = Some(val.clone()),
            "--threads" => a.threads = Some(val.parse().map_err(|_| "bad --threads")?),
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    if a.input.is_empty() || a.output.is_empty() {
        return Err("--in and --out are required".into());
    }
    Ok(a)
}

fn run(a: Args) -> Result<(), String> {
    if let Some(t) = a.threads {
        rayon::ThreadPoolBuilder::new().num_threads(t).build_global().map_err(|e| e.to_string())?;
    }
    let t0 = Instant::now();
    let text = fs::read_to_string(&a.input).map_err(|e| format!("read {}: {e}", a.input))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let recs: Vec<Rec> = lines
        .par_iter()
        .map(|l| serde_json::from_str::<Rec>(l).map_err(|e| format!("bad record: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let n = recs.len();
    eprintln!("gg-engine: {n} records parsed in {:?} on {} threads", t0.elapsed(), rayon::current_num_threads());

    let mut seeds = [0u64; NUM_PERM];
    for (i, s) in seeds.iter_mut().enumerate() {
        *s = mix((i + 1) as u64);
    }

    let eligible: Vec<u32> = (0..n as u32)
        .filter(|&i| recs[i as usize].instrs >= a.min_instrs && !recs[i as usize].mn.split_whitespace().next().is_none())
        .collect();

    // Prepared features, indexed by record index (None when ineligible).
    let t1 = Instant::now();
    let prepared: Vec<Option<Prepared>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let r = &recs[i];
            if r.instrs < a.min_instrs || r.mn.split_whitespace().next().is_none() {
                return None;
            }
            let shingles = shingle_hashes(&r.mn);
            let sig = minhash(&shingles, &seeds);
            Some(Prepared {
                shingles,
                sig,
                apis: sorted_unique(r.apis.clone()),
                consts: sorted_unique(r.consts.clone()),
                strs: sorted_unique(r.strs.clone()),
                expr: sorted_unique(r.expr.clone()),
            })
        })
        .collect();
    eprintln!("gg-engine: minhash done in {:?}", t1.elapsed());

    // ---- candidate generation ------------------------------------------------
    let t2 = Instant::now();
    let mut cand: Vec<(u32, u32)> = (0..BANDS)
        .into_par_iter()
        .flat_map_iter(|b| {
            let mut buckets: HashMap<u64, Vec<u32>> = HashMap::new();
            for &i in &eligible {
                let p = prepared[i as usize].as_ref().unwrap();
                buckets.entry(band_key(&p.sig, b)).or_default().push(i);
            }
            let mut out = Vec::new();
            for (_, mut m) in buckets {
                add_bucket_pairs(&mut m, &mut out);
            }
            out.into_iter()
        })
        .collect();

    // Exact-key buckets for cross-compiler matches the mnemonic stream would miss.
    let mut extra: Vec<(u32, u32)> = Vec::new();
    {
        let mut by_expr: HashMap<&[u64], Vec<u32>> = HashMap::new();
        let mut by_api: HashMap<&[String], Vec<u32>> = HashMap::new();
        let mut by_const: HashMap<&[String], Vec<u32>> = HashMap::new();
        for &i in &eligible {
            let p = prepared[i as usize].as_ref().unwrap();
            if !p.expr.is_empty() {
                by_expr.entry(&p.expr[..]).or_default().push(i);
            }
            if p.apis.len() >= 3 {
                by_api.entry(&p.apis[..]).or_default().push(i);
            }
            if p.consts.len() >= 2 {
                by_const.entry(&p.consts[..]).or_default().push(i);
            }
        }
        for (_, mut m) in by_expr {
            add_bucket_pairs(&mut m, &mut extra);
        }
        for (_, mut m) in by_api {
            add_bucket_pairs(&mut m, &mut extra);
        }
        for (_, mut m) in by_const {
            add_bucket_pairs(&mut m, &mut extra);
        }
    }
    cand.extend(extra);
    cand.par_sort_unstable();
    cand.dedup();
    eprintln!("gg-engine: {} candidate pairs in {:?}", cand.len(), t2.elapsed());

    // ---- scoring ------------------------------------------------------------------
    let t3 = Instant::now();
    let scored: Vec<(u32, u32, f64, [Option<f64>; 5])> = cand
        .par_iter()
        .filter_map(|&(x, y)| {
            let (rx, ry) = (&recs[x as usize], &recs[y as usize]);
            if let Some(q) = &a.query_scope {
                if &rx.scope != q && &ry.scope != q {
                    return None;
                }
            }
            let (px, py) = (prepared[x as usize].as_ref()?, prepared[y as usize].as_ref()?);
            let j = [
                jaccard(&px.shingles, &py.shingles),
                jaccard(&px.expr, &py.expr),
                jaccard(&px.apis, &py.apis),
                jaccard(&px.consts, &py.consts),
                jaccard(&px.strs, &py.strs),
            ];
            let w = [W_MN, W_EXPR, W_API, W_CONST, W_STR];
            let (mut num, mut den) = (0.0f64, 0.0f64);
            for k in 0..5 {
                if let Some(v) = j[k] {
                    num += w[k] * v;
                    den += w[k];
                }
            }
            if den == 0.0 {
                return None;
            }
            let score = num / den;
            if score >= a.threshold {
                Some((x, y, score, j))
            } else {
                None
            }
        })
        .collect();
    eprintln!("gg-engine: {} pairs above threshold in {:?}", scored.len(), t3.elapsed());

    // ---- top-k of at least one endpoint -----------------------------------------
    let order = |p: &(u32, u32, f64, [Option<f64>; 5]), q: &(u32, u32, f64, [Option<f64>; 5])| {
        q.2.partial_cmp(&p.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| recs[p.0 as usize].id.cmp(&recs[q.0 as usize].id))
            .then_with(|| recs[p.1 as usize].id.cmp(&recs[q.1 as usize].id))
    };
    let mut per: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, (x, y, _, _)) in scored.iter().enumerate() {
        per.entry(*x).or_default().push(idx);
        per.entry(*y).or_default().push(idx);
    }
    let mut keep = vec![false; scored.len()];
    for (_, mut list) in per {
        list.sort_by(|&p, &q| order(&scored[p], &scored[q]));
        for &idx in list.iter().take(a.top_k) {
            keep[idx] = true;
        }
    }
    let mut kept: Vec<&(u32, u32, f64, [Option<f64>; 5])> =
        scored.iter().enumerate().filter(|(i, _)| keep[*i]).map(|(_, s)| s).collect();
    kept.sort_by(|p, q| order(p, q));

    let edges: Vec<Edge> = kept
        .iter()
        .map(|(x, y, s, j)| {
            let (ia, ib) = (&recs[*x as usize].id, &recs[*y as usize].id);
            let (lo, hi) = if ia <= ib { (ia, ib) } else { (ib, ia) };
            Edge {
                a: lo.clone(),
                b: hi.clone(),
                score: round4(*s),
                mn: j[0].map(round4),
                expr: j[1].map(round4),
                api: j[2].map(round4),
                konst: j[3].map(round4),
                strs: j[4].map(round4),
            }
        })
        .collect();
    fs::write(&a.output, serde_json::to_vec(&edges).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write {}: {e}", a.output))?;
    eprintln!("gg-engine: {} edges written; total {:?}", edges.len(), t0.elapsed());
    Ok(())
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gg-engine: {e}");
            ExitCode::from(2)
        }
    }
}
