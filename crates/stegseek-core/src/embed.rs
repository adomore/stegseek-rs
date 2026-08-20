//! The embedder. Walks the Selector permutation, groups samples into vertices,
//! and corrects each vertex whose sample-sum ≠ the target EmbValue by modifying
//! its least-distorting sample (`getNearestTargetSampleValue`). Port of the
//! correctness core of `Embedder` (using the trivial/greedy matching — the
//! graph-matching distortion optimizer is a tracked follow-up; output is fully
//! interoperable with the original steghide).

use crate::bitstring::BitString;
use crate::error::{StegError, StegResult};
use crate::format::EmbedFile;
use crate::rng::RandomSource;
use crate::selector::Selector;

/// Embed `to_embed` (an n-ary BitString of EmbValues) into `cover` using the
/// permutation `selector`.
pub fn embed_into(
    cover: &mut dyn EmbedFile,
    to_embed: &BitString,
    selector: &mut Selector,
    rng: &mut dyn RandomSource,
) -> StegResult<()> {
    let m = cover.emb_value_modulus();
    let spv = cover.samples_per_vertex() as u32;
    let n_vertices = to_embed.nary_length();

    if (n_vertices as u64) * (spv as u64) > cover.num_samples() as u64 {
        let cap = cover.num_samples() / spv;
        return Err(StegError::Steghide(format!(
            "the cover file is too small to embed the data (capacity {cap} values, need {n_vertices})."
        )));
    }

    let mut sv_idx = 0u32;
    for v in 0..n_vertices {
        let target = to_embed.get_nary(v);
        let mut positions = [0u32; 8];
        let mut cur = 0u8;
        for j in 0..spv {
            let p = selector.at(sv_idx);
            sv_idx += 1;
            positions[j as usize] = p;
            cur = (cur + cover.get_embedded_value(p)) % m;
        }
        if cur == target {
            continue;
        }
        let delta = (target + m - cur) % m;
        // choose the sample whose correction distorts least
        let mut best_j = 0u32;
        let mut best_d = u32::MAX;
        let mut best_t = 0u8;
        for j in 0..spv {
            let p = positions[j as usize];
            let ev = cover.get_embedded_value(p);
            let nt = (ev + delta) % m;
            let d = cover.nearest_distance(p, nt);
            if d < best_d {
                best_d = d;
                best_j = j;
                best_t = nt;
            }
        }
        cover.apply_target(positions[best_j as usize], best_t, rng);
    }
    Ok(())
}

use crate::embdata::EmbData;
use stegseek_crypto::{EncryptionAlgorithm, EncryptionMode};

/// High-level embed: build the EmbData frame and embed it into the cover bytes,
/// returning the stego file bytes. Mirrors `Embedder` + `Session::EMBED`.
#[allow(clippy::too_many_arguments)]
pub fn embed_file(
    cover_bytes: Vec<u8>,
    cover_name: &str,
    passphrase: &[u8],
    embed_filename: &[u8],
    data: &[u8],
    enc_algo: EncryptionAlgorithm,
    enc_mode: EncryptionMode,
    compression: i32,
    checksum: bool,
    rng: &mut dyn RandomSource,
    radius_override: Option<u32>,
    goal: u32,
) -> StegResult<Vec<u8>> {
    let mut to_embed = EmbData::build_embed(
        passphrase,
        embed_filename,
        data,
        enc_algo,
        enc_mode,
        compression,
        checksum,
        rng,
    )?;
    let mut cover = crate::format::read_for_embed(cover_bytes, cover_name)?;
    to_embed.set_arity(cover.emb_value_modulus());
    let mut sel = Selector::from_passphrase(cover.num_samples(), passphrase);
    embed_into_matched(&mut *cover, &to_embed, &mut sel, rng, radius_override, goal)?;
    Ok(cover.to_stego_bytes())
}

/// Maximum number of graph vertices for which the matching optimizer runs
/// (beyond this, the O(V^2)-ish edge build is skipped and the greedy embedder
/// is used — same correctness, just no distortion optimization).
const MATCHING_VERTEX_CAP: usize = 8192;

struct GVertex {
    pos: Vec<u32>,
    ev: Vec<u8>,
    target: Vec<u8>,
}

/// Total distortion (sum of per-sample `calcDistance` of every change) — for
/// measuring the optimizer vs. the greedy embedder.
pub struct EmbedStats {
    pub matched_edges: usize,
    pub exposed_vertices: usize,
    /// total embedding distortion saved by the matching vs. the all-greedy fix
    /// (sum over matched edges of greedy_cost(v1)+greedy_cost(v2) - 2*weight).
    pub distortion_saved: u64,
}

/// Embed using steghide's graph-matching idea: vertices whose sample-sum ≠
/// target are matched into low-distortion *swaps* where possible (WKS-style
/// greedy minimum-weight matching); the rest fall back to the greedy
/// single-sample change. Interoperable with the original.
/// `radius_override` (from `-r/--radius`) replaces the per-format default
/// neighbourhood radius used when searching for beneficial swaps. `goal`
/// (from `-g/--goal`, 0..=100) is steghide's target matching percentage; here it
/// gates the optimizer — `goal == 0` skips matching entirely (pure greedy),
/// any positive value runs the greedy beneficial matcher as before.
pub fn embed_into_matched(
    cover: &mut dyn EmbedFile,
    to_embed: &BitString,
    selector: &mut Selector,
    rng: &mut dyn RandomSource,
    radius_override: Option<u32>,
    goal: u32,
) -> StegResult<EmbedStats> {
    let m = cover.emb_value_modulus();
    let spv = cover.samples_per_vertex() as usize;
    let n_vertices = to_embed.nary_length();
    if (n_vertices as u64) * (spv as u64) > cover.num_samples() as u64 {
        let cap = cover.num_samples() / spv as u32;
        return Err(StegError::Steghide(format!(
            "the cover file is too small to embed the data (capacity {cap} values, need {n_vertices})."
        )));
    }
    let radius = radius_override.unwrap_or_else(|| cover.radius());

    // build graph vertices (only the mismatched ones, as steghide does)
    let mut verts: Vec<GVertex> = Vec::new();
    let mut sv_idx = 0u32;
    for v in 0..n_vertices {
        let target = to_embed.get_nary(v);
        let mut pos = Vec::with_capacity(spv);
        let mut ev = Vec::with_capacity(spv);
        let mut msum = 0u8;
        for _ in 0..spv {
            let p = selector.at(sv_idx);
            sv_idx += 1;
            pos.push(p);
            let e = cover.get_embedded_value(p);
            ev.push(e);
            msum = (msum + e) % m;
        }
        if msum == target {
            continue; // already correct
        }
        let d = (target + m - msum) % m;
        let tv: Vec<u8> = ev.iter().map(|&e| (e + d) % m).collect();
        verts.push(GVertex {
            pos,
            ev,
            target: tv,
        });
    }

    let nv = verts.len();
    let mut matched = vec![false; nv];
    let mut matched_edges = 0usize;
    let mut saved = 0u64;

    // greedy single-sample cost per vertex (distortion if left exposed)
    let greedy_cost: Vec<u32> = verts
        .iter()
        .map(|vt| {
            (0..spv)
                .map(|i| cover.nearest_distance(vt.pos[i], vt.target[i]))
                .min()
                .unwrap_or(0)
        })
        .collect();

    if goal > 0 && nv <= MATCHING_VERTEX_CAP {
        // index samples by embedded value
        #[derive(Clone, Copy)]
        struct SRef {
            v: usize,
            i: usize,
        }
        let mut by_ev: std::collections::HashMap<u8, Vec<SRef>> = Default::default();
        for (vi, vt) in verts.iter().enumerate() {
            for i in 0..spv {
                by_ev.entry(vt.ev[i]).or_default().push(SRef { v: vi, i });
            }
        }
        // build swap edges: (weight, v1, i1, v2, i2)
        let mut edges: Vec<(u32, usize, usize, usize, usize)> = Vec::new();
        for (vi, vt) in verts.iter().enumerate() {
            for i in 0..spv {
                let t = vt.target[i];
                if let Some(cands) = by_ev.get(&t) {
                    for c in cands {
                        if c.v <= vi {
                            continue; // dedup + skip self-vertex
                        }
                        // edge valid iff partner's sample carries our needed value
                        // and ours carries theirs, and they are neighbours
                        if verts[c.v].target[c.i] == vt.ev[i] {
                            let d = cover.sample_distance(vt.pos[i], verts[c.v].pos[c.i]);
                            // an edge (swap) changes BOTH samples by `d`; only worth
                            // it when not costlier than fixing both vertices greedily
                            if d <= radius && 2 * d <= greedy_cost[vi] + greedy_cost[c.v] {
                                edges.push((d, vi, i, c.v, c.i));
                            }
                        }
                    }
                }
            }
        }
        // greedy minimum-weight maximal matching
        edges.sort_unstable_by_key(|e| e.0);
        for (w, v1, i1, v2, i2) in edges {
            if !matched[v1] && !matched[v2] {
                matched[v1] = true;
                matched[v2] = true;
                saved += (greedy_cost[v1] as u64 + greedy_cost[v2] as u64) - 2 * w as u64;
                cover.swap_samples(verts[v1].pos[i1], verts[v2].pos[i2]);
                matched_edges += 1;
            }
        }
    }

    // exposed (unmatched) vertices: greedy least-distortion single-sample change
    let mut exposed = 0usize;
    for (vi, vt) in verts.iter().enumerate() {
        if matched[vi] {
            continue;
        }
        let mut best_i = 0usize;
        let mut best_d = u32::MAX;
        for i in 0..spv {
            let d = cover.nearest_distance(vt.pos[i], vt.target[i]);
            if d < best_d {
                best_d = d;
                best_i = i;
            }
        }
        cover.apply_target(vt.pos[best_i], vt.target[best_i], rng);
        exposed += 1;
    }

    Ok(EmbedStats {
        matched_edges,
        exposed_vertices: exposed,
        distortion_saved: saved,
    })
}
