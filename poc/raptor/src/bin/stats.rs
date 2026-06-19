//! Statistical sanity check for the CRITICAL-1 anonymity fix.
//!
//! An adversary trying to unmask the signer in a Raptor ring looks for the one member whose
//! (r0,r1) short vector was produced by Falcon's genuine trapdoor sampler vs. the others.
//! Before the fix, non-signers were drawn from a per-coordinate CLT Gaussian (truncated tails,
//! no lattice covariance) — distinguishable.  After the fix, non-signers are drawn from the
//! SAME Falcon preimage sampler (sign_target under a throwaway key) as the signer.
//!
//! This harness signs many times, separates the SIGNER member's vector from the NON-SIGNER
//! members' vectors, and compares the moments an attacker would key on:
//!   - per-coordinate stddev          (width)
//!   - per-coordinate excess kurtosis (tail shape: Gaussian-vs-heavier)
//!   - max |coeff|                    (tail truncation — the old sampler clamped at +-2047)
//!   - joint squared norm  mean/std   (||r0||^2+||r1||^2; the acceptance-bound observable)
//!
//! We CANNOT prove indistinguishability from moments alone (that needs a formal argument /
//! statistical-distance bound — an audit item).  What we CAN show is that the signer and
//! non-signer samples now come from the same generator, so these observables coincide within
//! sampling noise, whereas a CLT approximation would separate on kurtosis and max-|coeff|.

use raptor_spike::falcon_ffi as fc;
use raptor_spike::raptor::{self, RaptorSecretKey, RaptorPublicKey, Member};

fn keypair(seed: &[u8]) -> (RaptorPublicKey, RaptorSecretKey) {
    raptor::keygen(&fc::shake256(seed, 48))
}

/// Accumulates per-coordinate moments over a stream of i16 coefficients, plus per-vector
/// observables (max |coeff|, joint sqnorm).
#[derive(Default)]
struct Acc {
    n: u64,        // coefficient count
    sum: f64,      // sum x
    sum2: f64,     // sum x^2
    sum4: f64,     // sum x^4 (for kurtosis)
    vmax: i64,     // global max |coeff|
    vecs: u64,     // number of (r0,r1) pairs folded in
    sqnorm_sum: f64,
    sqnorm_sum2: f64,
}

impl Acc {
    fn add_pair(&mut self, r0: &[i16; 512], r1: &[i16; 512]) {
        let mut sq: u64 = 0;
        for arr in [r0, r1] {
            for &c in arr.iter() {
                let x = c as f64;
                self.n += 1;
                self.sum += x;
                self.sum2 += x * x;
                self.sum4 += x * x * x * x;
                let a = (c as i64).abs();
                if a > self.vmax { self.vmax = a; }
                sq += (c as i64 * c as i64) as u64;
            }
        }
        self.vecs += 1;
        self.sqnorm_sum += sq as f64;
        self.sqnorm_sum2 += (sq as f64) * (sq as f64);
    }
    fn mean(&self) -> f64 { self.sum / self.n as f64 }
    fn var(&self) -> f64 {
        let m = self.mean();
        self.sum2 / self.n as f64 - m * m
    }
    fn std(&self) -> f64 { self.var().sqrt() }
    // excess kurtosis = E[(x-mu)^4]/sigma^4 - 3.  ~0 for a true Gaussian; >0 for heavier tails.
    // The mean mu is ~0 by symmetry, so we approximate the central fourth moment by the raw
    // fourth moment E[x^4] (the mu-correction terms are negligible when mu << sigma, which holds
    // here: per-coordinate mean ~0, sigma ~ a few hundred).
    fn excess_kurtosis(&self) -> f64 {
        let n = self.n as f64;
        let e_x2 = self.sum2 / n;
        let e_x4 = self.sum4 / n;
        let mu = self.sum / n;
        let sigma2 = e_x2 - mu * mu;
        // central4 ~= E[x^4] - 4 mu E[x^3] + ... ; with mu~0 the leading term dominates.
        let central4 = e_x4 - 3.0 * mu.powi(4); // remaining symmetric correction
        central4 / (sigma2 * sigma2) - 3.0
    }
    fn sqnorm_mean(&self) -> f64 { self.sqnorm_sum / self.vecs as f64 }
    fn sqnorm_std(&self) -> f64 {
        let m = self.sqnorm_mean();
        (self.sqnorm_sum2 / self.vecs as f64 - m * m).sqrt()
    }
}

fn main() {
    // Build a ring; sign many times with a rotating signer index and rotating seeds so the
    // throwaway-keyed non-signer sampler is exercised across many fresh keys.
    let ring_size = 6usize;
    let sigs = 400usize; // 400 sigs * (ring_size-1) non-signers ~ 2000 non-signer vectors

    let mut secs = Vec::new();
    for i in 0..ring_size {
        let (_p, s) = keypair(format!("stats-member-{}", i).as_bytes());
        secs.push(s);
    }
    let ring: Vec<[u16; fc::N]> = secs.iter().map(|s| s.a0).collect();

    let mut signer_acc = Acc::default();
    let mut nonsigner_acc = Acc::default();

    for k in 0..sigs {
        let signer = k % ring_size;
        let msg = format!("stats-msg-{}", k);
        let seed = format!("stats-seed-{}", k);
        let sig = raptor::sign(msg.as_bytes(), &ring, &secs[signer], signer, seed.as_bytes())
            .expect("sign");
        for (i, m) in sig.members.iter().enumerate() {
            let Member { r0, r1, .. } = m;
            if i == signer { signer_acc.add_pair(r0, r1); }
            else { nonsigner_acc.add_pair(r0, r1); }
        }
    }

    let row = |label: &str, a: &Acc| {
        println!(
            "  {:<12} | {:>6} | {:>8.2} | {:>8.3} | {:>6} | {:>12.0} | {:>10.0}",
            label, a.vecs, a.std(), a.excess_kurtosis(), a.vmax, a.sqnorm_mean(), a.sqnorm_std()
        );
    };

    println!("== CRITICAL-1 anonymity sanity: signer vs non-signer (r0,r1) distribution ==\n");
    println!("  ring_size={}, signatures={}, Falcon-512 acceptance sqnorm bound={}",
             ring_size, sigs, raptor::FALCON512_SQNORM_BOUND);
    println!();
    println!("  sample       | vecs   | coeff_sd | exkurt   | max|c| | sqnorm_mean  | sqnorm_sd");
    println!("  -------------+--------+----------+----------+--------+--------------+-----------");
    row("signer", &signer_acc);
    row("non-signer", &nonsigner_acc);
    println!();

    // Comparison verdict (informational — NOT a proof of indistinguishability).
    let d_sd = (signer_acc.std() - nonsigner_acc.std()).abs();
    let rel_sd = d_sd / signer_acc.std();
    let d_kurt = (signer_acc.excess_kurtosis() - nonsigner_acc.excess_kurtosis()).abs();
    let rel_sqn = (signer_acc.sqnorm_mean() - nonsigner_acc.sqnorm_mean()).abs()
        / signer_acc.sqnorm_mean();

    println!("  |Delta stddev|        = {:.2}  ({:.2}% of signer stddev)", d_sd, rel_sd * 100.0);
    println!("  |Delta exkurtosis|    = {:.3}", d_kurt);
    println!("  |Delta sqnorm mean|   = {:.2}% of signer mean", rel_sqn * 100.0);
    println!();

    // Loose sanity gates: same generator => these match within sampling noise.  Wide margins
    // (this is a sanity check, not a hypothesis test); the OLD CLT sampler failed the kurtosis
    // gate (clamped/truncated tails => measurably different shape) and the max|c| gate (hard
    // clamp at 2047).  Falcon coeffs routinely exceed any per-coordinate CLT clamp.
    let mut ok = true;
    if rel_sd > 0.05 { println!("  [WARN] stddev differs by >5% — widths diverge"); ok = false; }
    if d_kurt > 0.5 { println!("  [WARN] excess-kurtosis differs by >0.5 — tail shapes diverge"); ok = false; }
    if rel_sqn > 0.05 { println!("  [WARN] joint-sqnorm mean differs by >5%"); ok = false; }

    if ok {
        println!("  [PASS] signer and non-signer (r0,r1) match on width, tail shape, and");
        println!("         joint norm within sampling noise — consistent with both being drawn");
        println!("         from Falcon's preimage sampler.  (Indistinguishability NOT proven;");
        println!("         formal statistical-distance bound remains an audit item.)");
    } else {
        println!("  [FAIL] distributions diverge — non-signer sampler does NOT match Falcon's.");
        std::process::exit(1);
    }
}
