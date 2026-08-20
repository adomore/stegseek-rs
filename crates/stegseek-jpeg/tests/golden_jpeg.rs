use stegseek_jpeg::JpegImage;

fn datafile(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap()
}
fn fnv_coeffs(lin: &[i16], idx: &[u32]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &i in idx {
        let uv = lin[i as usize] as u16;
        h ^= (uv & 0xff) as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= (uv >> 8) as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
#[test]
fn baseline_matches_libjpeg() {
    let img = JpegImage::parse(&datafile("std.jpg")).unwrap();
    let (lin, idx) = img.linearize();
    assert_eq!(idx.len(), 3548, "std.jpg num_samples");
    assert_eq!(
        fnv_coeffs(&lin, &idx),
        0x214aa2257bc3f3eb,
        "std.jpg coeff fnv"
    );
}
#[test]
fn progressive_matches_libjpeg() {
    let img = JpegImage::parse(&datafile("prog.jpg")).unwrap();
    let (lin, idx) = img.linearize();
    assert_eq!(idx.len(), 4887, "prog.jpg num_samples");
    assert_eq!(
        fnv_coeffs(&lin, &idx),
        0x62ffbf2055db4382,
        "prog.jpg coeff fnv"
    );
}
