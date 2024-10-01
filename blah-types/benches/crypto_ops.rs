#![expect(clippy::unwrap_used, reason = "allow in benches")]
use std::hint::black_box;
use std::time::Instant;

use blah_types::msg::{ChatPayload, UserRegisterChallengeResponse, UserRegisterPayload};
use blah_types::{get_timestamp, Id, PubKey, SignExt, Signee, UserKey};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use rand::rngs::mock::StepRng;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

const SEED: u64 = 0xDEAD_BEEF_BEEF_DEAD;

fn bench_register_pow(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(SEED);

    let id_key_priv = SigningKey::from_bytes(&[0x1A; 32]);
    let id_key = PubKey::from(id_key_priv.verifying_key());
    let act_key_priv = SigningKey::from_bytes(&[0x2B; 32]);
    let act_key = PubKey::from(act_key_priv.verifying_key());
    let payload = UserRegisterPayload {
        id_key: id_key.clone(),
        server_url: "http://some.example.com".parse().unwrap(),
        id_url: "http://another.example.com".parse().unwrap(),
        challenge: Some(UserRegisterChallengeResponse::Pow { nonce: rng.gen() }),
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

fn avg_msg() -> ChatPayload {
    // The average text message length is 50.88 bytes (UTF-8), according to
    // the last 1 year data from <https://t.me/nixos_zhcn>
    ChatPayload {
        rich_text: "🤔️ average length message! 平均长度消息".into(),
        room: Id(1_234_567_890_000 << 16 | 0xDEAD),
    }
}

fn bench_msg_sign_verify(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(SEED);

    let id_key_priv = SigningKey::generate(rng);
    let act_key_priv = SigningKey::generate(rng);
    let id_key = PubKey::from(id_key_priv.verifying_key());
    let timestamp = 1_727_045_943 << 16; // The time when I writing this code.

    let msg = avg_msg();
    c.bench_function("msg-sign", |b| {
        let seq_rng = &mut StepRng::new(1, 1);
        b.iter(|| {
            black_box(msg.clone())
                .sign_msg_with(&id_key, &act_key_priv, timestamp, seq_rng)
                .unwrap()
        })
    });

    let signed = msg
        .sign_msg_with(&id_key, &act_key_priv, timestamp, rng)
        .unwrap();

    c.bench_function("msg-verify", |b| {
        b.iter(|| black_box(&signed).verify().unwrap());
    });
}

criterion_group!(benches, bench_register_pow, bench_msg_sign_verify);

criterion_main!(benches);
