/* abi_test.c — exercise the ccx_pq_* C ABI from plain C (the real consensus-side surface).
 * Proves the cdylib is callable with C types only: keygen -> sign -> verify -> nullifier,
 * plus canonicity and double-spend linkability via the C entry points. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern uint32_t ccx_pq_scheme_id(void);
extern size_t   ccx_pq_pubkey_bytes(void);
extern size_t   ccx_pq_seckey_bytes(void);
extern size_t   ccx_pq_nullifier_bytes(void);
extern int32_t  ccx_pq_pubkey_is_canonical(const uint8_t *pk, size_t pk_len);
extern int32_t  ccx_pq_keygen(const uint8_t *seed, size_t seed_len,
                              uint8_t *pk_out, size_t pk_cap, uint8_t *sk_out, size_t sk_cap);
extern int32_t  ccx_pq_nullifier(const uint8_t *sk, size_t sk_len,
                                 const uint8_t *pk, size_t pk_len, uint8_t *nf_out, size_t nf_cap);
extern int32_t  ccx_pq_sign(const uint8_t *msg, size_t msg_len,
                            const uint8_t *ring, size_t ring_count, size_t member_stride,
                            const uint8_t *sk, size_t sk_len, size_t signer_index,
                            uint8_t *sig_out, size_t *sig_len);
extern int32_t  ccx_pq_verify(const uint8_t *msg, size_t msg_len,
                              const uint8_t *ring, size_t ring_count, size_t member_stride,
                              const uint8_t *sig, size_t sig_len, uint8_t *nf_out, size_t nf_cap);

#define RING 4

int main(void) {
    size_t pkb = ccx_pq_pubkey_bytes();
    size_t skb = ccx_pq_seckey_bytes();
    size_t nfb = ccx_pq_nullifier_bytes();
    printf("scheme_id=0x%08x pubkey=%zu seckey=%zu nullifier=%zu\n",
           ccx_pq_scheme_id(), pkb, skb, nfb);

    uint8_t pk[RING][1024], sk[RING][256];
    for (int i = 0; i < RING; i++) {
        char seed[32];
        int n = snprintf(seed, sizeof seed, "c-abi-member-%d", i);
        if (ccx_pq_keygen((uint8_t*)seed, (size_t)n, pk[i], sizeof pk[i], sk[i], sizeof sk[i]) != 0) {
            printf("FAIL keygen %d\n", i); return 1;
        }
        if (ccx_pq_pubkey_is_canonical(pk[i], pkb) != 1) { printf("FAIL canonical %d\n", i); return 1; }
    }
    printf("PASS keygen + canonical for %d members\n", RING);

    /* contiguous ring buffer, stride = pkb */
    uint8_t ring[RING * 1024];
    for (int i = 0; i < RING; i++) memcpy(ring + i * pkb, pk[i], pkb);

    const char *msg = "C-ABI spend message";
    size_t signer = 2;
    uint8_t sig[65536]; size_t siglen = sizeof sig;
    if (ccx_pq_sign((const uint8_t*)msg, strlen(msg), ring, RING, pkb,
                    sk[signer], skb, signer, sig, &siglen) != 0) {
        printf("FAIL sign\n"); return 1;
    }
    printf("PASS sign: %zu bytes\n", siglen);

    uint8_t nf_v[64];
    if (ccx_pq_verify((const uint8_t*)msg, strlen(msg), ring, RING, pkb, sig, siglen, nf_v, sizeof nf_v) != 0) {
        printf("FAIL verify\n"); return 1;
    }
    printf("PASS verify\n");

    /* nullifier from sk must equal nullifier from verify */
    uint8_t nf_k[64];
    if (ccx_pq_nullifier(sk[signer], skb, pk[signer], pkb, nf_k, sizeof nf_k) != 0) { printf("FAIL nullifier\n"); return 1; }
    if (memcmp(nf_k, nf_v, nfb) != 0) { printf("FAIL nullifier mismatch\n"); return 1; }
    printf("PASS nullifier(sk) == nullifier(verify)\n");

    /* double-spend: same signer in a DIFFERENT ring -> same nullifier */
    uint8_t ring2[RING * 1024];
    /* rotate members so signer lands at index 0 in a different ring composition */
    memcpy(ring2 + 0 * pkb, pk[signer], pkb);
    memcpy(ring2 + 1 * pkb, pk[0], pkb);
    memcpy(ring2 + 2 * pkb, pk[1], pkb);
    memcpy(ring2 + 3 * pkb, pk[3], pkb);
    uint8_t sig2[65536]; size_t siglen2 = sizeof sig2;
    if (ccx_pq_sign((const uint8_t*)"other msg", 9, ring2, RING, pkb, sk[signer], skb, 0, sig2, &siglen2) != 0) {
        printf("FAIL sign2\n"); return 1;
    }
    uint8_t nf_v2[64];
    if (ccx_pq_verify((const uint8_t*)"other msg", 9, ring2, RING, pkb, sig2, siglen2, nf_v2, sizeof nf_v2) != 0) {
        printf("FAIL verify2\n"); return 1;
    }
    if (memcmp(nf_v, nf_v2, nfb) != 0) { printf("FAIL linkability: nullifiers differ for same signer\n"); return 1; }
    printf("PASS linkability: same signer, different ring -> identical nullifier\n");

    /* tamper: flip a sig byte -> verify must reject */
    sig[20] ^= 0xff;
    if (ccx_pq_verify((const uint8_t*)msg, strlen(msg), ring, RING, pkb, sig, siglen, nf_v, sizeof nf_v) == 0) {
        printf("FAIL tamper accepted\n"); return 1;
    }
    printf("PASS tamper rejected\n");

    printf("\nALL C-ABI CHECKS PASSED\n");
    return 0;
}
