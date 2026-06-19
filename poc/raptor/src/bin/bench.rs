// bench: stable size/timing table (more iterations) for the report.
use raptor_spike::abi;
use raptor_spike::falcon_ffi as fc;
use raptor_spike::raptor::{self, RaptorSecretKey, RaptorPublicKey};
use std::time::Instant;

fn kp(s: &[u8]) -> (RaptorPublicKey, RaptorSecretKey) {
    raptor::keygen(&fc::shake256(s, 48))
}

fn main() {
    // keygen timing
    let t = Instant::now();
    let iters_kg = 20;
    for i in 0..iters_kg { let _ = kp(format!("kg{}", i).as_bytes()); }
    println!("keygen: {:.1} ms/key (avg of {})", t.elapsed().as_secs_f64() * 1e3 / iters_kg as f64, iters_kg);

    println!("\nring | sig_bytes | sign_ms | verify_ms  (compact comp-encoded packing)");
    println!("-----+-----------+---------+----------");
    for &rs in &[2usize, 4, 6, 8, 16] {
        let mut secs = Vec::new();
        for i in 0..rs { secs.push(kp(format!("rm-{}-{}", rs, i).as_bytes()).1); }
        let ring: Vec<[u16; fc::N]> = secs.iter().map(|s| s.a0).collect();
        let signer = rs / 2;
        let m = b"benchmark message body";

        // sign timing (avg)
        let sign_iters = 20;
        let t0 = Instant::now();
        let mut last = None;
        for j in 0..sign_iters {
            let seed = format!("b{}", j);
            last = Some(raptor::sign(m, &ring, &secs[signer], signer, seed.as_bytes()).unwrap());
        }
        let sign_ms = t0.elapsed().as_secs_f64() * 1e3 / sign_iters as f64;
        let sig = last.unwrap();
        let sz = abi::pack(&sig).unwrap().len();

        // verify timing (avg)
        let verify_iters = 50;
        let t1 = Instant::now();
        for _ in 0..verify_iters { assert!(raptor::verify(m, &ring, &sig).is_ok()); }
        let verify_ms = t1.elapsed().as_secs_f64() * 1e3 / verify_iters as f64;

        println!("{:>4} | {:>9} | {:>7.2} | {:>8.2}", rs, sz, sign_ms, verify_ms);
    }
}
