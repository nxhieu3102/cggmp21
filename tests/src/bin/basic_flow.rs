// this binary crate is created by Truc Vy to test the cggmp21 library
use anyhow::Context;
use cggmp21::{
    key_share::Validate,
    progress::PerfProfiler,
    signing::{msg::Msg, SigningBuilder},
    DataToSign, ExecutionId,
};
use rand::Rng;
use rand_dev::DevRng;
use round_based::simulation::Simulation;
use sha2::Sha256;

type E = generic_ec::curves::Secp256k1;
type D = sha2::Sha256;
type L = cggmp21::security_level::SecurityLevel128;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let option = 4;

    // a random number generator that uses the
    // system's secure random number generator
    // it will print value of RUST_TESTS_SEED
    let mut rng = DevRng::new();

    // number of parties
    let n = 3;
    // threshold
    let t = 2;

    match option {
        0 => generate_primes(&mut rng),
        1 => {
            non_threshold_key_shares(&mut rng, n).await;
        }
        2 => {
            threshold_key_shares(&mut rng, n, t).await;
        }
        3 => {
            let mut aux_data = aux_data(&mut rng, n).await;
            precompute_multiexp_tables(&mut aux_data).await;
        }
        4 => {
            let mut non_threshold_key_shares = non_threshold_key_shares(&mut rng, n).await;
            let mut aux_data = aux_data(&mut rng, n).await;
            pre_signing(&mut rng, n, &mut non_threshold_key_shares, &mut aux_data).await;
        }
        5 => {
            let mut non_threshold_key_shares = non_threshold_key_shares(&mut rng, n).await;
            let mut aux_data = aux_data(&mut rng, n).await;
            signing(&mut rng, n, &mut non_threshold_key_shares, &mut aux_data).await;
        }
        _ => {}
    }
}

/// generate primes {p,q} with given security level
fn generate_primes(rng: &mut DevRng) {
    println!("### Test PregeneratedPrimes::generate()");
    let prime = cggmp21::PregeneratedPrimes::<L>::generate(rng);
    println!("prime: {:?}", prime);
    println!();
}

/// key shares for non-threshold
async fn non_threshold_key_shares(rng: &mut DevRng, n: u16) -> Vec<cggmp21::IncompleteKeyShare<E>> {
    println!("### Test key shares for non-threshold");

    // each protocol execution must have unique execution ID (eid)
    // all signers taking part in the protocol must share the same eid
    // eid is a list of bytes
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);
    println!("eid: {:?}", eid);

    // multiparty protocol simulator
    // TODO: why simulation contains:
    // ___ outgoing channel (to send message): stores internally all sent messages in entire protocol,
    // ___ next-party-index: ~ current number of parties in the protocol,
    // ___ next-message-id: ~ current number of messages in the protocol
    // simulator can add/connect new party into the protocol
    // simulator as a global state, manage the index of next party/message and channels
    let mut simulation = Simulation::<cggmp21::keygen::msg::non_threshold::Msg<E, L, D>>::new();

    // create multi-threads to
    // add n parties into the protocol
    // concurrently, run key share for each of them
    let outputs = (0..n).map(|i| {
        // add a party and create its own random generator
        let party = simulation.add_party();
        let mut party_rng = rng.fork();

        // profiles performance of the protocol for each party
        // can be embedded into protocol execution
        // keeps track of time passed between each step of protocol
        // obtain report that contains all the measurements
        let mut profiler = PerfProfiler::new();

        // setup and run the key-gen of party i
        // get the party's report after key-gen
        async move {
            let key_share = cggmp21::keygen(eid, i, n)
                .set_progress_tracer(&mut profiler)
                .set_security_level::<L>()
                .start(&mut party_rng, party)
                .await
                .context("keygen failed")?;
            let report = profiler.get_report().context("get perf report")?;
            Ok::<_, anyhow::Error>((key_share, report))
        }
    });

    // run the above threads
    let outputs = futures::future::try_join_all(outputs)
        .await
        .expect("non-threshold keygen failed");

    // print results
    println!("Key share: {:?}", outputs[0].0);
    /*
    example the key share
    that result is under the view point of each party
    the below result is from the first party

    Valid(
        DirtyCoreKeyShare {
            // id of the party
            i: 0,

            // public key information
            // ___ shared public key,
            // ___ commitments to secret shares
            key_info: DirtyKeyInfo {
                // elliptic curve
                curve: CurveName(
                    PhantomType(
                        PhantomData<
                            generic_ec_curves::rust_crypto::RustCryptoCurve<
                                k256::Secp256k1,
                                elliptic_curve::hash2curve::hash2field::expand_msg::xmd::ExpandMsgXmd<
                                    digest::core_api::wrapper::CoreWrapper<
                                        digest::core_api::ct_variable::CtVariableCoreWrapper<
                                            sha2::core_api::Sha256VarCore,
                                            typenum::uint::UInt<
                                                typenum::uint::UInt<
                                                    typenum::uint::UInt<
                                                        typenum::uint::UInt<
                                                            typenum::uint::UInt<
                                                                typenum::uint::UInt<
                                                                    typenum::uint::UTerm,
                                                                    typenum::bit::B1
                                                                >,
                                                                typenum::bit::B0
                                                            >,
                                                            typenum::bit::B0
                                                        >,
                                                        typenum::bit::B0
                                                    >,
                                                    typenum::bit::B0
                                                >,
                                                typenum::bit::B0
                                            >,
                                            sha2::OidSha256
                                        >
                                    >
                                >
                            >
                        >
                    )
                ),

                // protocol public key (X = g^x)
                shared_public_key: NonZero(
                    Point {
                        curve: "secp256k1",
                        value: "03fb0062dc786743c5ad3addcef858613ef40a0575dd6a8c9d88e58373b73eb906"
                    }
                ),

                // there are 3 parties in this protocol (included itself)
                // so, there are 3 public shares (public commitment) corresponding to 3 secret shares
                public_shares: [
                    NonZero(
                        Point {
                            curve: "secp256k1",
                            value: "0224ba6ae86480791b949ca15271ccd4a8578183925d7f1b3a42020e2551fc1ac7"
                        }
                    ),
                    NonZero(
                        Point {
                            curve: "secp256k1",
                            value: "033b512f266e8ed23534376ce1d9fc535ea8ce3085c6be163f102443d7fd4f4e08"
                        }
                    ),
                    NonZero(
                        Point {
                            curve: "secp256k1",
                            value: "0356b9b7afd20794b8f7385f0a772507dc0b193c71a7d793838982c3bf68775a75"
                        }
                    )
                ],
                // verifiable secret sharing setup,
                // true for threshold protocol
                vss_setup: None
            },

            // its own secret share (x_i)
            x: NonZero(SecretScalar)
        }
    );
    */
    println!("Report0:\n{}", outputs[0].1.clone().display_io(false));
    /*
    report of each party
    display_io(false) --> do not include time sending message or waiting for other parties
    the below example is under view point of the first party

    Protocol Performance:
    - Protocol took 11.89ms to complete
    In particular:
    - Stage: 53.96µs
        - Setup networking: 53.31µs (98.8%)
        - Unstaged: 651.00ns (1.2%)
    - Round 1: 9.06ms
        - Sample x_i, rid_i, chain_code: 8.21ms (90.6%)
        - Sample schnorr commitment: 604.67µs (6.7%)
        - Commit to public data: 243.67µs (2.7%)
        - Unstaged: 1.38µs (0.0%)
    - Round 2: 33.81µs
        - Hash received msgs (reliability check): 32.87µs (97.2%)
        - Unstaged: 933.00ns (2.8%)
    - Round 3: 1.03µs
        - Assert other parties hashed messages (reliability check): 703.00ns (68.1%)
        - Unstaged: 330.00ns (31.9%)
    - Round 4: 269.86µs
        - Validate decommitments: 230.48µs (85.4%)
        - Calculate challege rid: 36.78µs (13.6%)
        - Prove knowledge of `x_i`: 2.29µs (0.8%)
        - Unstaged: 308.00ns (0.1%)
    - Round 5: 2.47ms
        - Validate schnorr proofs: 2.47ms (100.0%)
        - Unstaged: 1.04µs (0.0%)
    */
    println!();

    // return the imcomplete key shares for the next steps
    let incomplete_key_shares = outputs.into_iter().map(|(k, _)| k).collect();

    incomplete_key_shares
}

/// key shares for threshold
async fn threshold_key_shares(
    rng: &mut DevRng,
    n: u16,
    t: u16,
) -> Vec<cggmp21::IncompleteKeyShare<E>> {
    println!("### Test key shares for threshold");

    // non_threshold_key_shares for more explainations

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut simulation = Simulation::<cggmp21::keygen::msg::threshold::Msg<E, L, D>>::with_capacity(
        // this protocol can contain ~2.n^2 messages
        (2 * n * n).into(),
    );

    // create multi-threads to
    // add n parties and run their key share
    let outputs = (0..n).map(|i| {
        let party = simulation.add_party();
        let mut party_rng = rng.fork();

        let mut profiler = PerfProfiler::new();

        async move {
            let key_share = cggmp21::keygen(eid, i, n)
                // set threshold for the threshold protocol
                .set_threshold(t)
                .set_progress_tracer(&mut profiler)
                .set_security_level::<L>()
                .start(&mut party_rng, party)
                .await
                .context("keygen failed")?;
            let report = profiler.get_report().context("get perf report")?;
            Ok::<_, anyhow::Error>((key_share, report))
        }
    });

    // run the above threads
    let outputs = futures::future::try_join_all(outputs)
        .await
        .expect("threshold keygen failed");

    // print results
    /*
    Sample result for threshold DKG
    under the first party view point

    Key shares: the same as non-threshold DKG, but contains VSS set up
        vss_setup: Some(
            VssSetup {
                // min_signers = threshold
                min_signers: 2,

                // `I[i]` corresponds to key share index of a $\ith$ signer
                I: [
                    NonZero(
                        Scalar {
                            curve: "secp256k1",
                            value: "0000000000000000000000000000000000000000000000000000000000000001"
                        }
                    ),
                    NonZero(
                        Scalar {
                            curve: "secp256k1",
                            value: "0000000000000000000000000000000000000000000000000000000000000002"
                        }
                    ),
                    NonZero(
                        Scalar {
                            curve: "secp256k1",
                            value: "0000000000000000000000000000000000000000000000000000000000000003"
                        }
                    )
                ]
            }
        )

    Protocol Performance:
    - Protocol took 22.00ms to complete
    In particular:
    - Stage: 6.34ms
        - Setup networking: 6.34ms (100.0%)
        - Unstaged: 519.00ns (0.0%)
    - Round 1: 3.68ms
        - Sample rid_i, schnorr commitment, polynomial, chain_code: 3.49ms (94.8%)
        - Commit to public data: 187.49µs (5.1%)
        - Unstaged: 3.61µs (0.1%)
    - Round 2: 33.89µs
        - Hash received msgs (reliability check): 33.39µs (98.5%)
        - Unstaged: 500.00ns (1.5%)
    - Round 3: 1.12µs
        - Assert other parties hashed messages (reliability check): 837.00ns (74.7%)
        - Unstaged: 283.00ns (25.3%)
    - Round 4: 9.05ms
        - Validate decommitments: 380.39µs (4.2%)
        - Validate data size: 1.36µs (0.0%)
        - Validate Feldmann VSS: 3.62ms (40.0%)
        - Compute rid: 6.19µs (0.1%)
        - Compute Ys: 4.17ms (46.0%)
        - Compute sigma: 624.63µs (6.9%)
        - Calculate challenge: 247.74µs (2.7%)
        - Prove knowledge of `sigma_i`: 2.14µs (0.0%)
        - Unstaged: 549.00ns (0.0%)
    - Round 5: 2.89ms
        - Validate schnorr proofs: 2.86ms (99.1%)
        - Derive resulting public key and other data: 15.03µs (0.5%)
        - Unstaged: 11.05µs (0.4%)
    */
    println!("Key shares: {:?}", outputs[0].0);
    println!("Report:\n{}", outputs[0].1.clone().display_io(false));
    println!();

    let incomplete_threshold_key_shares = outputs.into_iter().map(|(k, _)| k).collect();

    incomplete_threshold_key_shares
}

/// generate auxialiary data
async fn aux_data(rng: &mut DevRng, n: u16) -> Vec<cggmp21::key_share::AuxInfo<L>> {
    println!("### Test auxialiary data");

    // non_threshold_key_shares for more explainations

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut simulation = Simulation::<cggmp21::key_refresh::AuxOnlyMsg<D, L>>::new();

    let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<L>();

    let outputs = (0..n).map(|i| {
        let party = simulation.add_party();
        let mut party_rng = rng.fork();
        let pregen = primes.next().expect("Can't get pregenerated prime");

        let mut profiler = PerfProfiler::new();

        async move {
            let aux_data = cggmp21::aux_info_gen(eid, i, n, pregen)
                .set_progress_tracer(&mut profiler)
                .start(&mut party_rng, party)
                .await
                .context("aux data gen failed")?;
            let report = profiler.get_report().context("get perf report")?;
            Ok::<_, anyhow::Error>((aux_data, report))
        }
    });

    let outputs = futures::future::try_join_all(outputs)
        .await
        .expect("key refresh failed");

    println!("Auxiliary data generation protocol");
    println!("{}", outputs[0].1.clone().display_io(false));
    /*
    Protocol Performance:
    - Protocol took 8.14s to complete
    In particular:
    - Stage: 2.11ms
        - Retrieve auxiliary data: 4.13µs (0.2%)
        - Setup networking: 2.10ms (99.8%)
        - Unstaged: 739.00ns (0.0%)
    - Round 1: 971.16ms
        - Retrieve primes (p and q): 1.32µs (0.0%)
        - Compute paillier decryption key (N): 15.41µs (0.0%)
        - Generate auxiliary params r, λ, t, s: 8.26ms (0.9%)
        - Prove Πprm (ψˆ_i): 960.21ms (98.9%)
        - Sample random bytes: 6.10µs (0.0%)
        - Compute hash commitment and sample decommitment: 2.66ms (0.3%)
        - Unstaged: 2.44µs (0.0%)
    - Round 2: 34.95µs
        - Hash received msgs (reliability check): 33.93µs (97.1%)
        - Unstaged: 1.02µs (2.9%)
    - Round 3: 3.40µs
        - Assert other parties hashed messages (reliability check): 2.42µs (71.3%)
        - Unstaged: 974.00ns (28.7%)
    - Round 4: 4.96s
        - Validate round 1 decommitments: 5.40ms (0.1%)
        - Validate П_prm (ψ_i): 1.88s (37.9%)
        - Add together shared random bytes: 9.15µs (0.0%)
        - Compute П_mod (ψ_i): 2.93s (59.2%)
        - Assemble security params for П_fac (ф_i): 27.07µs (0.0%)
        - Compute П_fac (ф_i^j): 140.43ms (2.8%)
        - Unstaged: 5.22µs (0.0%)
    - Round 5: 2.21s
        - Validate ψ_j (П_mod): 2.06s (93.6%)
        - Validate ф_j (П_fac): 140.76ms (6.4%)
        - Assemble auxiliary info: 153.49µs (0.0%)
        - Unstaged: 2.40µs (0.0%)
     */
    println!();

    let aux_data = outputs.into_iter().map(|(a, _)| a).collect();

    aux_data
}

async fn precompute_multiexp_tables(aux_data: &mut Vec<cggmp21::key_share::AuxInfo<L>>) {
    *aux_data = aux_data
        .clone()
        .into_iter()
        .map(|aux_i| {
            let mut aux_i = aux_i.into_inner();
            aux_i.precompute_multiexp_tables().unwrap();
            aux_i.validate().unwrap()
        })
        .collect();

    println!(
        "Size of multiexp tables per key share: {} bytes",
        aux_data[0].multiexp_tables_size()
    );
    println!(
        "Size of exponents: {:?}",
        cggmp21::security_level::max_exponents_size::<L>()
    );
    /*
    Auxiliary data generation protocol
    Protocol Performance:
    - Protocol took 8.10s to complete
    In particular:
    - Stage: 1.37ms
        - Retrieve auxiliary data: 4.17µs (0.3%)
        - Setup networking: 1.37ms (99.7%)
        - Unstaged: 529.00ns (0.0%)
    - Round 1: 966.77ms
        - Retrieve primes (p and q): 1.42µs (0.0%)
        - Compute paillier decryption key (N): 7.05µs (0.0%)
        - Generate auxiliary params r, λ, t, s: 9.19ms (1.0%)
        - Prove Πprm (ψˆ_i): 954.87ms (98.8%)
        - Sample random bytes: 7.42µs (0.0%)
        - Compute hash commitment and sample decommitment: 2.70ms (0.3%)
        - Unstaged: 3.23µs (0.0%)
    - Round 2: 29.09µs
        - Hash received msgs (reliability check): 28.20µs (96.9%)
        - Unstaged: 890.00ns (3.1%)
    - Round 3: 1.76µs
        - Assert other parties hashed messages (reliability check): 1.36µs (77.0%)
        - Unstaged: 405.00ns (23.0%)
    - Round 4: 4.94s
        - Validate round 1 decommitments: 5.68ms (0.1%)
        - Validate П_prm (ψ_i): 1.88s (38.2%)
        - Add together shared random bytes: 12.16µs (0.0%)
        - Compute П_mod (ψ_i): 2.91s (58.8%)
        - Assemble security params for П_fac (ф_i): 20.22µs (0.0%)
        - Compute П_fac (ф_i^j): 142.47ms (2.9%)
        - Unstaged: 5.45µs (0.0%)
    - Round 5: 2.20s
        - Validate ψ_j (П_mod): 2.05s (93.4%)
        - Validate ф_j (П_fac): 144.46ms (6.6%)
        - Assemble auxiliary info: 162.79µs (0.0%)
        - Unstaged: 2.61µs (0.0%)


    Size of multiexp tables per key share: 826584 bytes
    Size of exponents: (2022, 3558)
     */
    println!();
}

async fn pre_signing(
    rng: &mut DevRng,
    n: u16,
    non_threshold_key_shares: &mut Vec<cggmp21::IncompleteKeyShare<E>>,
    aux_data: &mut Vec<cggmp21::key_share::AuxInfo<L>>,
) {
    println!("Test pre-signing on non-threshold multi-party");

    let shares = non_threshold_key_shares
        .into_iter()
        .zip(aux_data)
        .map(|(key_share, aux_data)| {
            cggmp21::key_share::KeyShare::from_parts((key_share.clone(), aux_data.clone()))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("couldn't complete a share");

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let parties_indexes_at_keygen = &(0..n).collect::<Vec<_>>();

    let mut simulation = Simulation::<Msg<E, D>>::new();

    let mut outputs = vec![];
    for (i, share) in (0..).zip(&shares) {
        let party = simulation.add_party();
        let mut party_rng = rng.fork();

        let mut profiler = PerfProfiler::new();

        outputs.push(async move {
            let pre_signature = SigningBuilder::new(eid, i, parties_indexes_at_keygen, share)
                .set_progress_tracer(&mut profiler)
                .generate_presignature(&mut party_rng, party)
                .await
                .context("pre-signing failed")?;

            let report = profiler.get_report().context("get perf report")?;
            Ok::<_, anyhow::Error>((pre_signature, report))
        });
    }

    // run the above threads
    let outputs = futures::future::try_join_all(outputs)
        .await
        .expect("signing failed");

    println!("Pre-signing protocol");
    println!("Pre-signature:\n{:?}", outputs[0].0);
    println!("Report:\n{}", outputs[0].1.clone().display_io(false));
    /*
    Presignature {
        R: NonZero(
            Point {
                curve: "secp256k1",
                value: "0299a92fb8036f2a9f7e8296137b1d3e16dd8c0c78958f5708af1b7fb54b5df309"
            }
        ),
        k: SecretScalar,
        chi: SecretScalar
    }

    Protocol Performance:
    - Protocol took 3.53s to complete
    In particular:
    - Stage: 841.71µs
        - Map t-out-of-n protocol to t-out-of-t: 701.15µs (83.3%)
        - Retrieve auxiliary data: 86.62µs (10.3%)
        - Precompute execution id and security params: 1.61µs (0.2%)
        - Setup networking: 52.00µs (6.2%)
        - Unstaged: 330.00ns (0.0%)
    - Round 1: 164.99ms
        - Generate local ephemeral secrets (k_i, y_i, p_i, v_i): 100.75µs (0.1%)
        - Encrypt G_i and K_i: 96.58ms (58.5%)
        - Prove ψ0_j: 68.31ms (41.4%)
        - Unstaged: 4.09µs (0.0%)
    - Round 2: 142.53µs
        - Hash received msgs (reliability check): 141.85µs (99.5%)
        - Unstaged: 686.00ns (0.5%)
    - Round 3: 1.87s
        - Assert other parties hashed messages (reliability check): 8.68µs (0.0%)
        - Verify psi0 proofs: 226.54ms (12.1%)
        - Sample random r, hat_r, s, hat_s, beta, hat_beta: 196.11µs (0.0%)
        - Encrypt D_ji: 59.04ms (3.2%)
        - Encrypt F_ji: 29.88ms (1.6%)
        - Encrypt hat_D_ji: 469.78ms (25.1%)
        - Encrypt hat_F_ji: 28.80ms (1.5%)
        - Prove psi_ji: 666.51ms (35.6%)
        - Prove psiˆ_ji: 176.07ms (9.4%)
        - Prove psi_prime_ji : 216.15ms (11.5%)
        - Unstaged: 4.62µs (0.0%)
    - Round 4: 1.33s
        - Retrieve auxiliary data: 9.56µs (0.0%)
        - Validate psi: 137.49ms (10.3%)
        - Validate hat_psi: 140.53ms (10.6%)
        - Validate psi_prime: 801.16ms (60.2%)
        - Compute Gamma, Delta_i, delta_i, chi_i: 180.56ms (13.6%)
        - Prove psi_prime_prime: 70.19ms (5.3%)
        - Unstaged: 7.61µs (0.0%)
    - Presig output: 162.40ms
        - Validate psi_prime_prime: 159.70ms (98.3%)
        - Calculate presignature: 2.70ms (1.7%)
        - Unstaged: 3.05µs (0.0%)
    */
    println!();
}

async fn signing(
    rng: &mut DevRng,
    n: u16,
    non_threshold_key_shares: &mut Vec<cggmp21::IncompleteKeyShare<E>>,
    aux_data: &mut Vec<cggmp21::key_share::AuxInfo<L>>,
) {
    println!("Test signing on non-threshold multi-party");

    let shares = non_threshold_key_shares
        .into_iter()
        .zip(aux_data)
        .map(|(key_share, aux_data)| {
            cggmp21::key_share::KeyShare::from_parts((key_share.clone(), aux_data.clone()))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("couldn't complete a share");

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let signers_indexes_at_keygen = &(0..n).collect::<Vec<_>>();

    let message_to_sign = b"Dfns rules!";
    let message_to_sign = DataToSign::digest::<Sha256>(message_to_sign);

    use cggmp21::signing::msg::Msg;
    let mut simulation = Simulation::<Msg<E, D>>::new();

    let mut outputs = vec![];
    for (i, share) in (0..).zip(&shares) {
        let party = simulation.add_party();
        let mut party_rng = rng.fork();

        let mut profiler = PerfProfiler::new();

        outputs.push(async move {
            let signature = cggmp21::signing(eid, i, signers_indexes_at_keygen, share)
                .set_progress_tracer(&mut profiler)
                .sign(&mut party_rng, party, message_to_sign)
                .await
                .context("signing failed")?;

            let report = profiler.get_report().context("get perf report")?;
            Ok::<_, anyhow::Error>((signature, report))
        });
    }

    // run the above threads
    let outputs = futures::future::try_join_all(outputs)
        .await
        .expect("signing failed");

    println!("Signing protocol");
    // println!("Signature:\n{:?}", outputs[0].0);
    println!("Report:\n{}", outputs[0].1.clone().display_io(false));
    /*
     Signing protocol
     Protocol Performance:
     - Protocol took 3.55s to complete
     In particular:
     - Stage: 775.85µs
         - Map t-out-of-n protocol to t-out-of-t: 677.85µs (87.4%)
         - Retrieve auxiliary data: 68.44µs (8.8%)
         - Precompute execution id and security params: 1.66µs (0.2%)
         - Setup networking: 27.50µs (3.5%)
         - Unstaged: 392.00ns (0.1%)
     - Round 1: 160.38ms
         - Generate local ephemeral secrets (k_i, y_i, p_i, v_i): 96.10µs (0.1%)
         - Encrypt G_i and K_i: 92.42ms (57.6%)
         - Prove ψ0_j: 67.86ms (42.3%)
         - Unstaged: 4.71µs (0.0%)
     - Round 2: 142.13µs
         - Hash received msgs (reliability check): 141.51µs (99.6%)
         - Unstaged: 625.00ns (0.4%)
     - Round 3: 1.88s
         - Assert other parties hashed messages (reliability check): 9.35µs (0.0%)
         - Verify psi0 proofs: 223.04ms (11.8%)
         - Sample random r, hat_r, s, hat_s, beta, hat_beta: 239.66µs (0.0%)
         - Encrypt D_ji: 58.50ms (3.1%)
         - Encrypt F_ji: 31.15ms (1.7%)
         - Encrypt hat_D_ji: 468.70ms (24.9%)
         - Encrypt hat_F_ji: 31.25ms (1.7%)
         - Prove psi_ji: 676.80ms (35.9%)
         - Prove psiˆ_ji: 176.67ms (9.4%)
         - Prove psi_prime_ji : 218.25ms (11.6%)
         - Unstaged: 6.98µs (0.0%)
     - Round 4: 1.33s
         - Retrieve auxiliary data: 10.57µs (0.0%)
         - Validate psi: 146.60ms (11.0%)
         - Validate hat_psi: 138.43ms (10.4%)
         - Validate psi_prime: 800.84ms (60.1%)
         - Compute Gamma, Delta_i, delta_i, chi_i: 178.45ms (13.4%)
         - Prove psi_prime_prime: 68.39ms (5.1%)
         - Unstaged: 5.85µs (0.0%)
     - Presig output: 173.25ms
         - Validate psi_prime_prime: 171.89ms (99.2%)
         - Calculate presignature: 1.36ms (0.8%)
         - Unstaged: 2.74µs (0.0%)
     - Partial signing: 51.15µs
     - Signature reconstruction: 2.01ms
    */
    println!();
}
