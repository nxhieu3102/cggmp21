//! End-to-end tests of the session API: parties run in-process, messages are routed as
//! serialized envelopes in a deliberately scrambled order.

use std::collections::VecDeque;
use std::sync::LazyLock;

use cggmp21::fast_paillier::DecryptionKey;
use cggmp21::PregeneratedPaillierKey;
use cggmp21_wasm::blob::{self, BlobKind};
use cggmp21_wasm::*;
use rand_core::OsRng;
use serde::de::DeserializeOwned;

trait Party {
    type Output;
    fn start(&mut self) -> Result<Step<Self::Output>, Error>;
    fn handle_incoming(&mut self, envelope: &Envelope) -> Result<Step<Self::Output>, Error>;
}

macro_rules! impl_party {
    ($($session:ty => $output:ty),*) => {$(
        impl Party for $session {
            type Output = $output;
            fn start(&mut self) -> Result<Step<$output>, Error> {
                <$session>::start(self)
            }
            fn handle_incoming(&mut self, envelope: &Envelope) -> Result<Step<$output>, Error> {
                <$session>::handle_incoming(self, envelope)
            }
        }
    )*};
}
impl_party!(
    KeygenSession => KeygenOutput,
    AuxInfoSession => AuxInfoOutput,
    SigningSession => SignatureOutput,
    PresigningSession => PresignatureOutput
);

struct Run<O> {
    outputs: Vec<Result<O, Error>>,
    envelopes: Vec<Envelope>,
}

/// Routes messages between parties until every party has an output or an error.
///
/// Delivery alternates between the newest and the oldest pending message, so parties receive
/// messages out of order and messages of future rounds before they are needed.
fn run<P: Party>(parties: Vec<P>) -> Run<P::Output> {
    let initial = parties.iter().map(|_| None).collect();
    run_with(parties, initial)
}

/// Like [`run`], but `initial[j] = Some(step)` means party `j` was already started by the
/// caller and `step` is what it returned
fn run_with<P: Party>(
    mut parties: Vec<P>,
    initial: Vec<Option<Result<Step<P::Output>, Error>>>,
) -> Run<P::Output> {
    let n = parties.len();
    let mut outputs: Vec<Option<Result<P::Output, Error>>> = (0..n).map(|_| None).collect();
    let mut pending = VecDeque::new();
    let mut envelopes = Vec::new();

    let mut record = |j: usize,
                      step: Result<Step<P::Output>, Error>,
                      outputs: &mut Vec<Option<Result<P::Output, Error>>>,
                      pending: &mut VecDeque<Envelope>| match step {
        Ok(step) => {
            for event in &step.events {
                assert!(event.t.is_finite());
            }
            for e in step.outgoing {
                assert_eq!(
                    usize::from(e.sender),
                    j,
                    "envelope sender must be the party"
                );
                envelopes.push(e.clone());
                pending.push_back(e);
            }
            if let Some(out) = step.output {
                assert!(outputs[j].is_none(), "output returned twice");
                outputs[j] = Some(Ok(out));
            }
        }
        Err(err) => outputs[j] = Some(Err(err)),
    };

    for ((j, party), initial) in parties.iter_mut().enumerate().zip(initial) {
        let step = initial.unwrap_or_else(|| party.start());
        record(j, step, &mut outputs, &mut pending);
    }
    let mut take_back = true;
    loop {
        let next = if take_back {
            pending.pop_back()
        } else {
            pending.pop_front()
        };
        take_back = !take_back;
        let Some(envelope) = next else { break };
        let recipients: Vec<usize> = match envelope.recipient {
            Some(j) => vec![usize::from(j)],
            None => (0..n)
                .filter(|&j| j != usize::from(envelope.sender))
                .collect(),
        };
        for j in recipients {
            if outputs[j].is_some() {
                continue;
            }
            let step = parties[j].handle_incoming(&envelope);
            record(j, step, &mut outputs, &mut pending);
        }
    }
    Run {
        outputs: outputs
            .into_iter()
            .map(|o| o.unwrap_or(Err(Error::Internal("party did not finish"))))
            .collect(),
        envelopes,
    }
}

fn unwrap_all<O>(run: Run<O>) -> (Vec<O>, Vec<Envelope>) {
    let outputs = run
        .outputs
        .into_iter()
        .enumerate()
        .map(|(j, o)| o.unwrap_or_else(|e| panic!("party {j} failed: {e}")))
        .collect();
    (outputs, run.envelopes)
}

fn eid(tag: &str) -> Vec<u8> {
    format!("cggmp21-wasm test {tag}").into_bytes()
}

fn keygen(tag: &str, n: u16, t: u16, ranks: Option<Vec<u16>>) -> Vec<KeygenOutput> {
    let parties = (0..n)
        .map(|i| {
            KeygenSession::new(
                KeygenConfig {
                    execution_id: eid(tag),
                    i,
                    n,
                    t,
                    ranks: ranks.clone(),
                },
                OsRng,
            )
            .unwrap()
        })
        .collect();
    let (outputs, _) = unwrap_all(run(parties));
    outputs
}

fn pregenerated_paillier_keys() -> Vec<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Keys {
        paillier_keys: Vec<DecryptionKey>,
    }
    let keys: Keys = serde_json::from_str(include_str!(
        "../../test-data/precomputed_paillier_keys.json"
    ))
    .unwrap();
    keys.paillier_keys
        .into_iter()
        .map(|dec| {
            let key = PregeneratedPaillierKey::<L>::new(dec).expect("test key has valid size");
            blob::encode(BlobKind::PaillierKey, &key).unwrap()
        })
        .collect()
}

/// Aux info of 3 parties, generated once and shared by tests (aux info does not depend on the key)
static AUX_INFO_3: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    let keys = pregenerated_paillier_keys();
    let parties = (0..3)
        .map(|i| {
            AuxInfoSession::new(
                AuxInfoConfig {
                    execution_id: eid("aux"),
                    i,
                    n: 3,
                    paillier_key: keys[usize::from(i)].clone(),
                },
                OsRng,
            )
            .unwrap()
        })
        .collect();
    let (outputs, envelopes) = unwrap_all(run(parties));
    report_sizes::<cggmp21::key_refresh::AuxOnlyMsg<D, L>>("aux info", &envelopes);
    outputs.into_iter().map(|o| o.aux_info).collect()
});

fn complete(keygen: &[KeygenOutput]) -> Vec<Vec<u8>> {
    keygen
        .iter()
        .zip(AUX_INFO_3.iter())
        .map(|(k, aux)| complete_key_share(&k.key_share, aux).unwrap())
        .collect()
}

fn signing_config(tag: &str, key_shares: &[Vec<u8>], signers: &[u16], i: usize) -> SigningConfig {
    SigningConfig {
        execution_id: eid(tag),
        i: i as u16,
        signers: signers.to_vec(),
        key_share: key_shares[usize::from(signers[i])].clone(),
        message: None,
    }
}

fn sign(
    tag: &str,
    key_shares: &[Vec<u8>],
    signers: &[u16],
    message: &[u8],
) -> Vec<SignatureOutput> {
    let parties = (0..signers.len())
        .map(|i| {
            let mut config = signing_config(tag, key_shares, signers, i);
            config.message = Some(message.to_vec());
            SigningSession::new(config, OsRng).unwrap()
        })
        .collect();
    let (outputs, envelopes) = unwrap_all(run(parties));
    report_sizes::<cggmp21::signing::msg::Msg<E, D>>("signing", &envelopes);
    outputs
}

fn presign_and_sign(
    tag: &str,
    key_shares: &[Vec<u8>],
    signers: &[u16],
    public_key: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let parties = (0..signers.len())
        .map(|i| {
            PresigningSession::new(signing_config(tag, key_shares, signers, i), OsRng).unwrap()
        })
        .collect();
    let (presigs, _) = unwrap_all(run(parties));
    let partials: Vec<Vec<u8>> = presigs
        .iter()
        .map(|p| issue_partial_signature(&p.presignature, message).unwrap())
        .collect();
    combine_partial_signatures(public_key, message, partials.iter().map(|p| p.as_slice())).unwrap()
}

/// Prints CBOR (wire format) vs JSON size of all messages of a protocol run
fn report_sizes<M: serde::Serialize + DeserializeOwned>(protocol: &str, envelopes: &[Envelope]) {
    let cbor: usize = envelopes.iter().map(|e| e.payload.len()).sum();
    let json: usize = envelopes
        .iter()
        .map(|e| {
            let msg: M = ciborium::from_reader(e.payload.as_slice()).unwrap();
            serde_json::to_vec(&msg).unwrap().len()
        })
        .sum();
    eprintln!(
        "{protocol}: {} messages, CBOR {cbor} bytes, JSON {json} bytes",
        envelopes.len()
    );
}

/// Verifies with an independent ECDSA implementation (k256)
fn k256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) {
    use k256::ecdsa::signature::Verifier;
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(signature).unwrap();
    vk.verify(message, &sig)
        .expect("k256 rejects the threshold signature");
}

fn assert_same_public_key(keygen: &[KeygenOutput]) -> Vec<u8> {
    let pk = keygen[0].public_key.clone();
    assert_eq!(pk.len(), 33);
    assert!(keygen.iter().all(|k| k.public_key == pk));
    pk
}

#[test]
fn threshold_keygen_aux_sign_presign() {
    let keygen = keygen("keygen 2-of-3", 3, 2, None);
    let public_key = assert_same_public_key(&keygen);
    for (j, k) in keygen.iter().enumerate() {
        let info = key_share_info(&k.key_share).unwrap();
        assert!(!info.complete);
        assert_eq!((info.i, info.n, info.t), (j as u16, 3, 2));
        assert_eq!(info.public_key, public_key);
    }
    let shares = complete(&keygen);
    assert!(key_share_info(&shares[1]).unwrap().complete);

    let message = b"threshold ECDSA in the browser";
    let sigs = sign("sign [0, 2]", &shares, &[0, 2], message);
    let sig = sigs[0].signature.clone();
    assert!(sigs
        .iter()
        .all(|s| s.signature == sig && s.public_key == public_key));
    assert!(verify_signature(&public_key, message, &sig).unwrap());
    k256_verify(&public_key, message, &sig);
    assert!(!verify_signature(&public_key, b"another message", &sig).unwrap());
    let mut tampered = sig.clone();
    tampered[40] ^= 1;
    assert!(!verify_signature(&public_key, message, &tampered).unwrap());

    // the signer set and its order are free
    let sig = sign("sign [2, 1, 0]", &shares, &[2, 1, 0], message);
    k256_verify(&public_key, message, &sig[0].signature);

    let sig = presign_and_sign("presign [1, 2]", &shares, &[1, 2], &public_key, message);
    assert!(verify_signature(&public_key, message, &sig).unwrap());
    k256_verify(&public_key, message, &sig);
}

#[test]
fn hierarchical_threshold_keygen_and_sign() {
    let keygen = keygen("htss keygen", 3, 2, Some(vec![0, 0, 1]));
    let public_key = assert_same_public_key(&keygen);
    assert_eq!(
        key_share_info(&keygen[2].key_share).unwrap().ranks,
        Some(vec![0, 0, 1])
    );
    let shares = complete(&keygen);
    let message = b"hierarchical";
    let sig = sign("htss sign", &shares, &[0, 2], message);
    k256_verify(&public_key, message, &sig[0].signature);
}

#[test]
fn partial_signatures_from_wrong_message_are_rejected() {
    let keygen = keygen("keygen partial", 3, 2, None);
    let public_key = assert_same_public_key(&keygen);
    let shares = complete(&keygen);
    let parties = (0..2)
        .map(|i| {
            PresigningSession::new(signing_config("presign", &shares, &[0, 1], i), OsRng).unwrap()
        })
        .collect();
    let (presigs, _) = unwrap_all(run(parties));
    let partials = [
        issue_partial_signature(&presigs[0].presignature, b"message").unwrap(),
        issue_partial_signature(&presigs[1].presignature, b"other message").unwrap(),
    ];
    let err = combine_partial_signatures(
        &public_key,
        b"message",
        partials.iter().map(|p| p.as_slice()),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "{err}");
}

#[test]
fn mismatched_execution_id_aborts() {
    let parties = (0..3)
        .map(|i| {
            let tag = if i == 2 { "other run" } else { "this run" };
            KeygenSession::new(
                KeygenConfig {
                    execution_id: eid(tag),
                    i,
                    n: 3,
                    t: 2,
                    ranks: None,
                },
                OsRng,
            )
            .unwrap()
        })
        .collect();
    let run = run(parties);
    assert!(run.outputs.iter().all(|o| o.is_err()));
    assert!(
        run.outputs
            .iter()
            .any(|o| matches!(o, Err(Error::Protocol(_)))),
        "at least one party must detect the mismatch"
    );
}

#[test]
fn rejected_messages_do_not_break_the_session() {
    let config = |i| KeygenConfig {
        execution_id: eid("rejections"),
        i,
        n: 3,
        t: 2,
        ranks: None,
    };
    let mut parties: Vec<_> = (0..3)
        .map(|i| KeygenSession::new(config(i), OsRng).unwrap())
        .collect();
    let first = parties[1].start().unwrap();
    assert!(!first.outgoing.is_empty());
    let good = first.outgoing[0].clone();
    assert_eq!(good.sender, 1);

    let rejected = |e: Result<Step<KeygenOutput>, Error>| {
        assert!(
            matches!(e, Err(Error::InvalidMessage { .. })),
            "{:?}",
            e.err()
        )
    };
    // claims to come from the recipient itself
    rejected(parties[1].handle_incoming(&good));
    // sender index out of range
    rejected(parties[0].handle_incoming(&Envelope {
        sender: 3,
        ..good.clone()
    }));
    // p2p message for another party
    rejected(parties[0].handle_incoming(&Envelope {
        recipient: Some(2),
        ..good.clone()
    }));
    // garbage payload
    rejected(parties[0].handle_incoming(&Envelope {
        payload: vec![0xff; 17],
        ..good.clone()
    }));
    // truncated payload
    let mut truncated = good.clone();
    truncated.payload.truncate(good.payload.len() / 2);
    rejected(parties[2].handle_incoming(&truncated));
    assert!(matches!(parties[1].start(), Err(Error::Misuse(_))));

    // messages arriving before `start` are queued
    for envelope in &first.outgoing {
        for j in [0, 2] {
            if envelope.recipient.is_none() || envelope.recipient == Some(j) {
                let step = parties[usize::from(j)].handle_incoming(envelope).unwrap();
                assert!(step.outgoing.is_empty() && step.output.is_none());
            }
        }
    }

    // the same sessions still complete the protocol
    let already_started = Step {
        outgoing: Vec::new(),
        events: Vec::new(),
        output: None,
    };
    let (outputs, _) = unwrap_all(run_with(
        parties,
        vec![None, Some(Ok(already_started)), None],
    ));
    assert_same_public_key(&outputs);
}

#[test]
fn invalid_configs_and_blobs_are_rejected() {
    let bad_keygen = |i, n, t, ranks| {
        KeygenSession::new(
            KeygenConfig {
                execution_id: eid("bad"),
                i,
                n,
                t,
                ranks,
            },
            OsRng,
        )
        .err()
        .expect("config must be rejected")
    };
    bad_keygen(3, 3, 2, None);
    bad_keygen(0, 3, 4, None);
    bad_keygen(0, 3, 1, None);
    bad_keygen(0, 3, 2, Some(vec![0, 0]));
    bad_keygen(0, 3, 2, Some(vec![0, 0, 2]));

    let keygen = keygen("blobs", 3, 2, None);
    let aux = &AUX_INFO_3[0];
    // swapped arguments: kinds are checked
    assert!(matches!(
        complete_key_share(aux, &keygen[0].key_share),
        Err(Error::InvalidBlob { .. })
    ));
    // aux info of another party index
    assert!(complete_key_share(&keygen[0].key_share, &AUX_INFO_3[1]).is_err());
    // corrupted blob
    let mut corrupted = keygen[0].key_share.clone();
    let len = corrupted.len();
    corrupted.truncate(len - 3);
    assert!(complete_key_share(&corrupted, aux).is_err());

    let shares = complete(&keygen);
    let signing =
        |signers: Vec<u16>, i: u16, share: usize, message: Option<Vec<u8>>| SigningConfig {
            execution_id: eid("bad signing"),
            i,
            signers,
            key_share: shares[share].clone(),
            message,
        };
    let msg = || Some(b"m".to_vec());
    // too few signers
    assert!(SigningSession::new(signing(vec![0], 0, 0, msg()), OsRng).is_err());
    // duplicates
    assert!(SigningSession::new(signing(vec![0, 0], 0, 0, msg()), OsRng).is_err());
    // signers[i] is not the share's index
    assert!(SigningSession::new(signing(vec![0, 1], 1, 0, msg()), OsRng).is_err());
    // unknown party
    assert!(SigningSession::new(signing(vec![0, 3], 0, 0, msg()), OsRng).is_err());
    // signing needs a message, presigning must not get one
    assert!(SigningSession::new(signing(vec![0, 1], 0, 0, None), OsRng).is_err());
    assert!(PresigningSession::new(signing(vec![0, 1], 0, 0, msg()), OsRng).is_err());
    // incomplete key share cannot sign
    let mut incomplete = signing(vec![0, 1], 0, 0, msg());
    incomplete.key_share = keygen[0].key_share.clone();
    assert!(SigningSession::new(incomplete, OsRng).is_err());
}

#[test]
fn paillier_key_generation_reports_progress() {
    let mut events = Vec::new();
    let key = generate_paillier_key(&mut OsRng, 0., &mut |e| events.push(e)).unwrap();
    assert_eq!(blob::kind_of(&key).unwrap(), BlobKind::PaillierKey);
    for which in [0, 1] {
        assert!(
            events
                .iter()
                .any(|e| matches!(e, PaillierProgress::PrimeFound { which: w, .. } if *w == which)),
            "no PrimeFound for {which}"
        );
    }
    // the generated key is accepted by aux info generation
    AuxInfoSession::new(
        AuxInfoConfig {
            execution_id: eid("generated key"),
            i: 0,
            n: 2,
            paillier_key: key,
        },
        OsRng,
    )
    .unwrap();
}
