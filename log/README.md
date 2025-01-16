# How to run

## 1. Run binary crates

### 1.1. `measure_perf`:
* Source code: `tests/src/bin/measure_perf.rs`
* Run command:
    ```=
    cargo run --bin measure_perf > ./log/measure-perf-log.txt
    ```
* Result (log): `./log/measure-perf-log.txt`

### 1.2. `precompute_shares`:
* Source code: `tests/src/bin/precompute_shares.rs`
* Run command:
    ```=
    // precompute shares
    cargo run --bin precompute_shares --features="hd-wallet" -- shares > log.txt

    // precompute primes
    cargo run --bin precompute_shares --features="hd-wallet" -- primes > log.txt

    // precompute old-shares
    cargo run --bin precompute_shares --features="hd-wallet" -- old-shares > log.txt
    ```
* Result (log): `./log/measure-perf-log.txt`

## 2. Benchmarks
Can not redirect the output into a file (because of stderr), follow these steps:

```=
// 1. Create a script file:
nano run_bench.sh

// 2. Add the following content:
// #!/bin/bash
// cargo bench > ./log/benches.txt 2>&1

// 3. Save and close the file, then make it executable:
chmod +x run_bench.sh

// 4. Run the scripts
./run_bench.sh
```

The result is written into `./log/benches.txt`