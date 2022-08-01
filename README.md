# cairo-sha256

Computes SHA256 of 'input'. Inputs of arbitrary length are supported.


## Usage

To use this function, split the input into (up to) 14 words of 32 bits (big endian).

To compute `sha256('Hello world')`, use:

    input = [1214606444, 1864398703, 1919706112]

where:
```python
1214606444 == int.from_bytes(b'Hell', 'big')
1864398703 == int.from_bytes(b'o wo', 'big')
1919706112 == int.from_bytes(b'rld\x00', 'big')  # Note the '\x00' padding.
```

For example:
```cairo
let (hello_world) = alloc()
assert hello_world[0] = 'hell'
assert hello_world[1] = 'o wo'
assert hello_world[2] = 'rld\x00'

let (local sha256_ptr_start : felt*) = alloc()
let sha256_ptr = sha256_ptr_start
let sha256_ptr_end = sha256_ptr_start
let (hash) = sha256{sha256_ptr=sha256_ptr, sha256_ptr_end=sha256_ptr_end}(hello_world, 11)
finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr_end)
```

Output is an array of 8 32-bit words (big endian).

Note: You must call finalize_sha2() at the end of the program. Otherwise, this function
is not sound and a malicious prover may return a wrong result.
Note: the interface of this function may change in the future.

## Development

The library uses [Protostar](https://docs.swmansion.com/protostar/) for development.

Run tests with:
```
protostar test
```

Extension of the starkware implementation at: https://github.com/starkware-libs/cairo-examples/blob/master/sha256/sha256.cairo