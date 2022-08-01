
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.registers import get_label_location
from starkware.cairo.common.invoke import invoke
from starkware.cairo.common.alloc import alloc

from src.sha256 import sha256, finalize_sha256

# Ported from https://github.com/Th0rgal/sphinx/blob/b85376cfb53e17cfa52fbeeb1f4560229f71a690/tests/test_sha256.cairo

@view
func test_sha256_hello_world{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (hello_world) = alloc()
    assert hello_world[0] = 'hell'
    assert hello_world[1] = 'o wo'
    assert hello_world[2] = 'rld\x00'

    let (local sha256_ptr_start : felt*) = alloc()
    let sha256_ptr = sha256_ptr_start
    let sha256_ptr_end = sha256_ptr_start
    let (hash) = sha256{sha256_ptr=sha256_ptr, sha256_ptr_end=sha256_ptr_end}(hello_world, 11)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr_end)

    let a = hash[0]
    assert a = 3108841401
    let b = hash[1]
    assert b = 2471312904
    let c = hash[2]
    assert c = 2771276503
    let d = hash[3]
    assert d = 3665669114
    let e = hash[4]
    assert e = 3297046499
    let f = hash[5]
    assert f = 2052292846
    let g = hash[6]
    assert g = 2424895404
    let h = hash[7]
    assert h = 3807366633

    return ()
end

# @view
# func test_sha256_multichunks{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
#     alloc_locals

#     let (phrase) = alloc()
#     # phrase="this is an example message which should take multiple chunks"
#     # 01110100 01101000 01101001 01110011
#     assert phrase[0] = 1952999795
#     # 00100000 01101001 01110011 00100000
#     assert phrase[1] = 543781664
#     # 01100001 01101110 00100000 01100101
#     assert phrase[2] = 1634607205
#     # 01111000 01100001 01101101 01110000
#     assert phrase[3] = 2019650928
#     # 01101100 01100101 00100000 01101101
#     assert phrase[4] = 1818566765
#     # 01100101 01110011 01110011 01100001
#     assert phrase[5] = 1702064993
#     # 01100111 01100101 00100000 01110111
#     assert phrase[6] = 1734680695
#     # 01101000 01101001 01100011 01101000
#     assert phrase[7] = 1751737192
#     # 00100000 01110011 01101000 01101111
#     assert phrase[8] = 544434287
#     # 01110101 01101100 01100100 00100000
#     assert phrase[9] = 1970037792
#     # 01110100 01100001 01101011 01100101
#     assert phrase[10] = 1952541541
#     # 00100000 01101101 01110101 01101100
#     assert phrase[11] = 544044396
#     # 01110100 01101001 01110000 01101100
#     assert phrase[12] = 1953067116
#     # 01100101 00100000 01100011 01101000
#     assert phrase[13] = 1696621416
#     # 01110101 01101110 01101011 01110011
#     assert phrase[14] = 1970170739

#     let (local sha256_ptr : felt*) = alloc()
#     let (hash) = sha256{sha256_ptr=sha256_ptr}(phrase, 60)

#     let a = hash[0]
#     assert a = 3714276112
#     let b = hash[1]
#     assert b = 759782134
#     let c = hash[2]
#     assert c = 1331117438
#     let d = hash[3]
#     assert c = 1331117438
#     let e = hash[4]
#     assert e = 699003633
#     let f = hash[5]
#     assert f = 2214481798
#     let g = hash[6]
#     assert g = 3208491254
#     let h = hash[7]
#     assert h = 789740750

#     return ()
# end

# test vectors from: https://www.di-mgt.com.au/sha_testvectors.html

@view
func test_sha256_0bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (empty) = alloc()
    let (local sha256_ptr_start : felt*) = alloc()
    let sha256_ptr = sha256_ptr_start
    let sha256_ptr_end = sha256_ptr_start
    let (hash) = sha256{sha256_ptr=sha256_ptr, sha256_ptr_end=sha256_ptr_end}(empty, 0)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr_end)

    let a = hash[0]
    assert a = 0xe3b0c442
    let b = hash[1]
    assert b = 0x98fc1c14
    let c = hash[2]
    assert c = 0x9afbf4c8
    let d = hash[3]
    assert d = 0x996fb924
    let e = hash[4]
    assert e = 0x27ae41e4
    let f = hash[5]
    assert f = 0x649b934c
    let g = hash[6]
    assert g = 0xa495991b
    let h = hash[7]
    assert h = 0x7852b855


    return ()
end

@view
func test_sha256_24bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (local sha256_ptr_start : felt*) = alloc()
    let sha256_ptr = sha256_ptr_start
    let sha256_ptr_end = sha256_ptr_start
    let (hash) = sha256{sha256_ptr=sha256_ptr, sha256_ptr_end=sha256_ptr_end}(new ('abc\x00'), 3)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr_end)

    let a = hash[0]
    assert a = 0xba7816bf
    let b = hash[1]
    assert b = 0x8f01cfea
    let c = hash[2]
    assert c = 0x414140de
    let d = hash[3]
    assert d = 0x5dae2223
    let e = hash[4]
    assert e = 0xb00361a3
    let f = hash[5]
    assert f = 0x96177a9c
    let g = hash[6]
    assert g = 0xb410ff61
    let h = hash[7]
    assert h = 0xf20015ad

    return ()
end

# @view
# func test_sha256_448bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
#     alloc_locals

#     let (input) = alloc()
#     assert input[0] = 'abcd'
#     assert input[1] = 'bcde'
#     assert input[2] = 'cdef'
#     assert input[3] = 'defg'
#     assert input[4] = 'efgh'
#     assert input[5] = 'fghi'
#     assert input[6] = 'ghij'
#     assert input[7] = 'hijk'
#     assert input[8] = 'ijkl'
#     assert input[9] = 'jklm'
#     assert input[10] = 'klmn'
#     assert input[11] = 'lmno'
#     assert input[12] = 'mnop'
#     assert input[13] = 'nopq'

#     let (local sha256_ptr : felt*) = alloc()
#     let (hash) = sha256{sha256_ptr=sha256_ptr}(input, 56)
#     let a = hash[0]
#     assert a = 0x248d6a61
#     let b = hash[1]
#     assert b = 0xd20638b8
#     let c = hash[2]
#     assert c = 0xe5c02693
#     let d = hash[3]
#     assert d = 0x0c3e6039
#     let e = hash[4]
#     assert e = 0xa33ce459
#     let f = hash[5]
#     assert f = 0x64ff2167
#     let g = hash[6]
#     assert g = 0xf6ecedd4
#     let h = hash[7]
#     assert h = 0x19db06c1

#     return ()
# end

# @view
# func test_sha256_896bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
#     alloc_locals

#     let (input) = alloc()
#     assert input[0] = 'abcd'
#     assert input[1] = 'bcde'
#     assert input[2] = 'fghi'
#     assert input[3] = 'cdef'
#     assert input[4] = 'ghij'
#     assert input[5] = 'defg'
#     assert input[6] = 'hijk'
#     assert input[7] = 'efgh'
#     assert input[8] = 'ijkl'
#     assert input[9] = 'fghi'
#     assert input[10] = 'jklm'
#     assert input[11] = 'ghij'
#     assert input[12] = 'klmn'
#     assert input[13] = 'hijk'
#     assert input[14] = 'lmno'
#     assert input[15] = 'ijkl'
#     assert input[16] = 'mnop'
#     assert input[17] = 'jklm'
#     assert input[18] = 'nopq'
#     assert input[19] = 'klmn'
#     assert input[20] = 'opqr'
#     assert input[21] = 'lmno'
#     assert input[22] = 'pqrs'
#     assert input[23] = 'mnop'
#     assert input[24] = 'qrst'
#     assert input[25] = 'nopq'
#     assert input[26] = 'rstu'

#     let (local sha256_ptr : felt*) = alloc()
#     let (hash) = sha256{sha256_ptr=sha256_ptr}(input, 112)
#     let a = hash[0]
#     assert a = 0xcf5b16a7
#     let b = hash[1]
#     assert b = 0x78af8380
#     let c = hash[2]
#     assert c = 0x036ce59e
#     let d = hash[3]
#     assert d = 0x7b049237
#     let e = hash[4]
#     assert e = 0x0b249b11
#     let f = hash[5]
#     assert f = 0xe8f07a51
#     let g = hash[6]
#     assert g = 0xafac4503
#     let h = hash[7]
#     assert h = 0x7afee9d1

#     return ()
# end

@view
func print_hash{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}(a: felt, b: felt, c: felt, d: felt, e: felt, f: felt, g: felt, h: felt):
    %{ print("output hash") %}
    %{ print("{:032b}".format(ids.a)) %}
    %{ print("{:032b}".format(ids.b)) %}
    %{ print("{:032b}".format(ids.c)) %}
    %{ print("{:032b}".format(ids.d)) %}
    %{ print("{:032b}".format(ids.e)) %}
    %{ print("{:032b}".format(ids.f)) %}
    %{ print("{:032b}".format(ids.g)) %}
    %{ print("{:032b}".format(ids.h)) %}
    return ()
end