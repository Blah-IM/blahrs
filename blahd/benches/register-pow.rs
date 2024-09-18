#![expect(clippy::unwrap_used, reason = "allow in benches")]
use std::hint::black_box;
use std::time::Instant;

use blah_types::{get_timestamp, PubKey, Signee, UserKey, UserRegisterPayload};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

fn bench_register_pow(c: &mut Criterion) {
    let rng = &mut thread_rng();

    let id_key_priv = SigningKey::from_bytes(&[0x1A; 32]);
    let id_key = PubKey(id_key_priv.verifying_key().to_bytes());
    let act_key_priv = SigningKey::from_bytes(&[0x2B; 32]);
    let act_key = PubKey(act_key_priv.verifying_key().to_bytes());
    let payload = UserRegisterPayload {
        id_key: id_key.clone(),
        server_url: "http://some.example.com".parse().unwrap(),
        id_url: "http://another.example.com".parse().unwrap(),
        challenge_nonce: rng.gen(),
    };
    let mut signee = Signee {
        nonce: 0,
        payload,
        timestamp: get_timestamp(),
        user: UserKey { id_key, act_key },
    };

    c.bench_function("register_pow_iter", |b| {
        b.iter_custom(|iters| {
            signee.nonce = rng.gen();

            let inst = Instant::now();
            for _ in 0..iters {
                let hash = {
                    let signee = serde_jcs::to_string(&signee).unwrap();
                    let mut h = Sha256::new();
                    h.update(&signee);
                    h.finalize()
                };
                let leading_zeros = hash
                    .iter()
                    .position(|&b| b != 0)
                    .map_or(256, |i| i as u32 * 8 + hash[i].leading_zeros());
                black_box(leading_zeros);
                signee.nonce = signee.nonce.wrapping_add(1);
            }
            inst.elapsed()
        });
    });
}

criterion_group!(benches, bench_register_pow);
criterion_main!(benches);
