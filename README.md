# Linux kernel siphash re-implementation in Python

This repo contains a re-implementation in Python 3 of selected `siphash_*()` functions in the Linux kernel.

The implemented functions are:

- `siphash(key, data)`
- `siphash_1u64(key, first)`
- `siphash_2u64(key, first, second)`
- `siphash_3u64(key, first, second, third)`
- `siphash_4u64(key, first, second, third, forth)`
- `siphash_1u32(key, first)`
- `siphash_3u32(key, first, second, third)`
