impl JpegImage {
#[allow(clippy::too_many_arguments)]
fn decode_scan(
    &mut self,
    data: &[u8],
    scan_start: usize,
    scan_comps: &[(u8, usize, usize)],
    ss: usize,
    se: usize,
    ah: u32,
    al: u32,
    dc_tables: &[HuffTable; 4],
    ac_tables: &[HuffTable; 4],
) -> Result<usize> {
    let interleaved = scan_comps.len() > 1;
    let mut sc: Vec<usize> = Vec::new();
    for &(cs, td, ta) in scan_comps {
        // Huffman table selectors index 4-entry tables; a corrupt SOS can carry
        // 0..15, so reject rather than index out of bounds later.
        if td >= 4 || ta >= 4 {
            return Err(JpegError::Corrupt("bad scan table selector".into()));
        }
        let ci = self
            .components
            .iter()
            .position(|c| c.id == cs)
            .ok_or_else(|| JpegError::Corrupt("scan component id".into()))?;
        self.components[ci].td = td;
        self.components[ci].ta = ta;
        sc.push(ci);
    }
    // A scan must reference at least one component (the non-interleaved branch
    // indexes `sc[0]`).
    if sc.is_empty() {
        return Err(JpegError::Corrupt("scan has no components".into()));
    }
    // Spectral selection must stay within a block's 64 coefficients; a corrupt
    // SOS could set Ss/Se to 255 and drive `NATURAL_ORDER[k]` (0..63) out of
    // bounds in the AC decoders.
    if se > 63 || ss > se {
        return Err(JpegError::Corrupt("bad spectral selection".into()));
    }
    let mut dc_pred = vec![0i32; sc.len()];
    let mut eob_run = 0u32;
    let mut br = BitReader::new(data, scan_start);
    let ri = self.restart_interval;
    let mut left = if ri > 0 { ri } else { usize::MAX };
    let baseline = !self.progressive;

    if interleaved {
        let max_h = self.components.iter().map(|c| c.h).max().unwrap();
        let max_v = self.components.iter().map(|c| c.v).max().unwrap();
        let mcus_w = divru(self.width, 8 * max_h);
        let mcus_h = divru(self.height, 8 * max_v);
        for my in 0..mcus_h {
            for mx in 0..mcus_w {
                for (s, &ci) in sc.iter().enumerate() {
                    let (h, v, wib_pad, td, ta) = {
                        let c = &self.components[ci];
                        (c.h, c.v, c.wib_pad, c.td, c.ta)
                    };
                    for by in 0..v {
                        for bx in 0..h {
                            let pos = (my * v + by) * wib_pad + (mx * h + bx);
                            let block = self.components[ci]
                                .blocks
                                .get_mut(pos)
                                .ok_or_else(|| JpegError::Corrupt("scan block index out of range".into()))?;
                            if baseline {
                                dec_baseline(block, &mut br, &dc_tables[td], &ac_tables[ta], &mut dc_pred[s])?;
                            } else if ah == 0 {
                                dec_dc_first(block, &mut br, &dc_tables[td], &mut dc_pred[s], al)?;
                            } else {
                                dec_dc_refine(block, &mut br, al);
                            }
                        }
                    }
                }
                left -= 1;
                if left == 0 && !(my == mcus_h - 1 && mx == mcus_w - 1) {
                    br.restart();
                    for d in dc_pred.iter_mut() {
                        *d = 0;
                    }
                    // (no eob_run reset: interleaved scans are baseline/DC and
                    // never use progressive EOB-run state)
                    left = ri;
                }
            }
        }
    } else {
        let ci = sc[0];
        let (wib_real, hib_real, wib_pad, td, ta) = {
            let c = &self.components[ci];
            (c.wib_real, c.hib_real, c.wib_pad, c.td, c.ta)
        };
        for by in 0..hib_real {
            for bx in 0..wib_real {
                let pos = by * wib_pad + bx;
                let block = self.components[ci]
                    .blocks
                    .get_mut(pos)
                    .ok_or_else(|| JpegError::Corrupt("scan block index out of range".into()))?;
                if baseline {
                    dec_baseline(block, &mut br, &dc_tables[td], &ac_tables[ta], &mut dc_pred[0])?;
                } else if ss == 0 {
                    if ah == 0 {
                        dec_dc_first(block, &mut br, &dc_tables[td], &mut dc_pred[0], al)?;
                    } else {
                        dec_dc_refine(block, &mut br, al);
                    }
                } else if ah == 0 {
                    dec_ac_first(block, &mut br, &ac_tables[ta], ss, se, al, &mut eob_run)?;
                } else {
                    dec_ac_refine(block, &mut br, &ac_tables[ta], ss, se, al, &mut eob_run)?;
                }
                left -= 1;
                if left == 0 && !(by == hib_real - 1 && bx == wib_real - 1) {
                    br.restart();
                    dc_pred[0] = 0;
                    eob_run = 0;
                    left = ri;
                }
            }
        }
    }
    Ok(find_next_marker(data, scan_start))
}

}
