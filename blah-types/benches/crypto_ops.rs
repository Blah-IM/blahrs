#![expect(clippy::unwrap_used, reason = "allow in benches")]
use std::hint::black_box;
use std::time::Instant;

use blah_types::msg::{ChatPayload, UserRegisterChallengeResponse, UserRegisterPayload};
use blah_types::{Id, PubKey, SignExt, Signee, UserKey, get_timestamp};
use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use sha2::{Digest, Sha256};

const SEED: u64 = 0xDEAD_BEEF_BEEF_DEAD;

const MOCK_PRIV_KEY1: [u8; 32] = *b"this is the testing private key1";
const MOCK_PRIV_KEY2: [u8; 32] = *b"that is the 2nd testing privkey.";

fn bench_register_pow(c: &mut Criterion) {
    let nonce_rng = &mut SmallRng::seed_from_u64(SEED);

    let id_key_priv = SigningKey::from_bytes(&MOCK_PRIV_KEY1);
    let id_key = PubKey::from(id_key_priv.verifying_key());
    let act_key_priv = SigningKey::from_bytes(&MOCK_PRIV_KEY2);
    let act_key = PubKey::from(act_key_priv.verifying_key());
    let payload = UserRegisterPayload {
        id_key: id_key.clone(),
        server_url: "http://some.example.com".parse().unwrap(),
        id_url: "http://another.example.com".parse().unwrap(),
        challenge: Some(UserRegisterChallengeResponse::Pow {
            nonce: nonce_rng.random(),
        }),
    };
    let mut signee = Signee {
        nonce: 0,
        payload,
        timestamp: get_timestamp(),
        user: UserKey { id_key, act_key },
    };

    c.bench_function("register_pow_iter", |b| {
        b.iter_custom(|iters| {
            signee.nonce = nonce_rng.random();

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
        room: Id((1_234_567_890_000 << 16) | 0xDEAD),
    }
}

fn bench_msg_sign_verify(c: &mut Criterion) {
    let id_key_priv = SigningKey::from_bytes(&MOCK_PRIV_KEY1);
    let act_key_priv = SigningKey::from_bytes(&MOCK_PRIV_KEY2);
    let id_key = PubKey::from(id_key_priv.verifying_key());
    let timestamp = 1_727_045_943 << 16; // The time when I writing this code.

    let msg = avg_msg();
    c.bench_function("msg-sign", |b| {
        // FIXME: Provide a deterministic signing method using a given nonce?
        let fixed_nonce_rng = &mut SmallRng::seed_from_u64(SEED);
        b.iter(|| {
            black_box(msg.clone())
                .sign_msg_with(&id_key, &act_key_priv, timestamp, fixed_nonce_rng)
                .unwrap()
        })
    });

    let rng = &mut SmallRng::seed_from_u64(SEED);
    let signed = msg
        .sign_msg_with(&id_key, &act_key_priv, timestamp, rng)
        .unwrap();

    c.bench_function("msg-verify", |b| {
        b.iter(|| black_box(&signed).verify().unwrap());
    });
}

criterion_group!(benches, bench_register_pow, bench_msg_sign_verify);

criterion_main!(benches);
