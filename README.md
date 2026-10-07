# wicuvanity

Generate WireGuard keypairs with a chosen Base64 public-key prefix on an NVIDIA GPU.

## Build

Requires Meson, CUDA and [cxxopts](https://github.com/jarro2783/cxxopts).
The build targets the visible GPU; binaries are not necessarily portable.

```sh
meson setup builddir --buildtype release
meson install -C builddir
```

For slow CUDA 13.1 compilation: `meson configure builddir -Dcuda_args=-Ofc=min`.

## Usage

```sh
CUDA_VISIBLE_DEVICES=0 ./builddir/wicuvanity --stats --in 6 Hayzam
```

Matching is case-insensitive; use `--case-sensitive` for exact capitalization.
`--in N` searches the first N characters; set N to the needle length for a prefix.
`--stats` prints throughput and approximate mean ETA to stderr, not a deadline.
Impossible Base64 patterns are rejected. Search continues until interrupted.

## Benchmarks

RTX 3070, CUDA 13.1, rare-prefix workload; median kernel throughput over five runs.
Original uses default device optimizations; current uses `-Ofc=min`.

| Version | Million keys/sec |
| --- | ---: |
| Original (`4aaee15`) | 1.66 |
| Current | 8.96 |

**5.4× throughput**, or about 81% less search time. A six-letter case-insensitive
prefix averages roughly 10.8 minutes before, 2.0 minutes now.

Keys use five 51-bit field limbs and independent ChaCha20-derived private scalars
seeded by the OS CSPRNG.

## Tests

Host tests require C++20 and OpenSSL headers; GPU tests also need Python `cryptography`.

```sh
meson setup buildtests tests -Db_sanitize=address,undefined
meson test -C buildtests --print-errorlogs
CUDA_VISIBLE_DEVICES=0 python3 tests/gpu.py ./builddir/wicuvanity
```

## Credits

- [shtrophic](https://git.sr.ht/~shtrophic/wicuvanity): original wicuvanity implementation.
- Brian Warner: [wireguard-vanity-address](https://github.com/warner/wireguard-vanity-address).
- Shengqi Chen (Harry-Chen) and Brian Warner: [wg-vanity](https://github.com/Harry-Chen/wg-vanity), source of the five-limb arithmetic.
- Martin Kleppmann: [Curve25519 notes](https://martin.kleppmann.com/papers/curve25519.pdf).

[MIT license](LICENSE).
