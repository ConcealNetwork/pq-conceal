// katprint: print ONLY the keygen KAT digest (hex) for this build.  Used by the cross-config
// FP-determinism sweep: rebuild under perturbing opt/FP flags and confirm the digest is identical.
use raptor_spike::raptor;

fn main() {
    let d = raptor::keygen_kat_digest();
    let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", hex);
}
