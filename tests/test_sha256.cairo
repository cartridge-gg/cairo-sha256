
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

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(hello_world, 11)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

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

@view
func test_sha256_multichunks{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (phrase) = alloc()
    # phrase="this is an example message which should take multiple chunks"
    # 01110100 01101000 01101001 01110011
    assert phrase[0] = 1952999795
    # 00100000 01101001 01110011 00100000
    assert phrase[1] = 543781664
    # 01100001 01101110 00100000 01100101
    assert phrase[2] = 1634607205
    # 01111000 01100001 01101101 01110000
    assert phrase[3] = 2019650928
    # 01101100 01100101 00100000 01101101
    assert phrase[4] = 1818566765
    # 01100101 01110011 01110011 01100001
    assert phrase[5] = 1702064993
    # 01100111 01100101 00100000 01110111
    assert phrase[6] = 1734680695
    # 01101000 01101001 01100011 01101000
    assert phrase[7] = 1751737192
    # 00100000 01110011 01101000 01101111
    assert phrase[8] = 544434287
    # 01110101 01101100 01100100 00100000
    assert phrase[9] = 1970037792
    # 01110100 01100001 01101011 01100101
    assert phrase[10] = 1952541541
    # 00100000 01101101 01110101 01101100
    assert phrase[11] = 544044396
    # 01110100 01101001 01110000 01101100
    assert phrase[12] = 1953067116
    # 01100101 00100000 01100011 01101000
    assert phrase[13] = 1696621416
    # 01110101 01101110 01101011 01110011
    assert phrase[14] = 1970170739

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(phrase, 60)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    let a = hash[0]
    assert a = 3714276112
    let b = hash[1]
    assert b = 759782134
    let c = hash[2]
    assert c = 1331117438
    let d = hash[3]
    assert c = 1331117438
    let e = hash[4]
    assert e = 699003633
    let f = hash[5]
    assert f = 2214481798
    let g = hash[6]
    assert g = 3208491254
    let h = hash[7]
    assert h = 789740750

    return ()
end

# test vectors from: https://www.di-mgt.com.au/sha_testvectors.html

@view
func test_sha256_0bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (empty) = alloc()
    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(empty, 0)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

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

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(new ('abc\x00'), 3)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

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

@view
func test_sha256_448bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (input) = alloc()
    assert input[0] = 'abcd'
    assert input[1] = 'bcde'
    assert input[2] = 'cdef'
    assert input[3] = 'defg'
    assert input[4] = 'efgh'
    assert input[5] = 'fghi'
    assert input[6] = 'ghij'
    assert input[7] = 'hijk'
    assert input[8] = 'ijkl'
    assert input[9] = 'jklm'
    assert input[10] = 'klmn'
    assert input[11] = 'lmno'
    assert input[12] = 'mnop'
    assert input[13] = 'nopq'

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(input, 56)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    let a = hash[0]
    assert a = 0x248d6a61
    let b = hash[1]
    assert b = 0xd20638b8
    let c = hash[2]
    assert c = 0xe5c02693
    let d = hash[3]
    assert d = 0x0c3e6039
    let e = hash[4]
    assert e = 0xa33ce459
    let f = hash[5]
    assert f = 0x64ff2167
    let g = hash[6]
    assert g = 0xf6ecedd4
    let h = hash[7]
    assert h = 0x19db06c1

    return ()
end

@view
func test_sha256_896bits{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (input) = alloc()
    assert input[0] = 'abcd'
    assert input[1] = 'efgh'
    assert input[2] = 'bcde'
    assert input[3] = 'fghi'
    assert input[4] = 'cdef'
    assert input[5] = 'ghij'
    assert input[6] = 'defg'
    assert input[7] = 'hijk'
    assert input[8] = 'efgh'
    assert input[9] = 'ijkl'
    assert input[10] = 'fghi'
    assert input[11] = 'jklm'
    assert input[12] = 'ghij'
    assert input[13] = 'klmn'
    assert input[14] = 'hijk'
    assert input[15] = 'lmno'
    assert input[16] = 'ijkl'
    assert input[17] = 'mnop'
    assert input[18] = 'jklm'
    assert input[19] = 'nopq'
    assert input[20] = 'klmn'
    assert input[21] = 'opqr'
    assert input[22] = 'lmno'
    assert input[23] = 'pqrs'
    assert input[24] = 'mnop'
    assert input[25] = 'qrst'
    assert input[26] = 'nopq'
    assert input[27] = 'rstu'

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(input, 112)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    let a = hash[0]
    assert a = 0xcf5b16a7
    let b = hash[1]
    assert b = 0x78af8380
    let c = hash[2]
    assert c = 0x036ce59e
    let d = hash[3]
    assert d = 0x7b049237
    let e = hash[4]
    assert e = 0x0b249b11
    let f = hash[5]
    assert f = 0xe8f07a51
    let g = hash[6]
    assert g = 0xafac4503
    let h = hash[7]
    assert h = 0x7afee9d1

    return ()
end

@view
func test_sha256_client_data{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}():
    alloc_locals

    let (client_data_json) = alloc()
    assert client_data_json[0] = 2065855609
    assert client_data_json[1] = 1885676090
    assert client_data_json[2] = 578250082
    assert client_data_json[3] = 1635087464
    assert client_data_json[4] = 1848534885
    assert client_data_json[5] = 1948396578
    assert client_data_json[6] = 1667785068
    assert client_data_json[7] = 1818586727
    assert client_data_json[8] = 1696741922
    assert client_data_json[9] = 813183028
    assert client_data_json[10] = 879047521
    assert client_data_json[11] = 1684224052
    assert client_data_json[12] = 895825200
    assert client_data_json[13] = 828518449
    assert client_data_json[14] = 1664497968
    assert client_data_json[15] = 878994482
    assert client_data_json[16] = 1647338340
    assert client_data_json[17] = 811872312
    assert client_data_json[18] = 878862896
    assert client_data_json[19] = 825373744
    assert client_data_json[20] = 959854180
    assert client_data_json[21] = 859398963
    assert client_data_json[22] = 825636148
    assert client_data_json[23] = 942761062
    assert client_data_json[24] = 1667327286
    assert client_data_json[25] = 896999980
    assert client_data_json[26] = 577729129
    assert client_data_json[27] = 1734962722
    assert client_data_json[28] = 975333492
    assert client_data_json[29] = 1953526586
    assert client_data_json[30] = 791634799
    assert client_data_json[31] = 1853125231
    assert client_data_json[32] = 1819043186
    assert client_data_json[33] = 761606451
    assert client_data_json[34] = 1886665079
    assert client_data_json[35] = 2004233840
    assert client_data_json[36] = 1919252073
    assert client_data_json[37] = 1702309475
    assert client_data_json[38] = 1634890866
    assert client_data_json[39] = 1768187749
    assert client_data_json[40] = 778528546
    assert client_data_json[41] = 740451186
    assert client_data_json[42] = 1869837135
    assert client_data_json[43] = 1919510377
    assert client_data_json[44] = 1847736934
    assert client_data_json[45] = 1634497381
    assert client_data_json[46] = 2097152000

    let (local sha256_ptr : felt*) = alloc()
    let sha256_ptr_start = sha256_ptr
    let (hash) = sha256{sha256_ptr=sha256_ptr}(client_data_json, 185)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    let a = hash[0]
    assert a = 0x08ad1974
    let b = hash[1]
    assert b = 0x216096a7
    let c = hash[2]
    assert c = 0x6ff36a54
    let d = hash[3]
    assert d = 0x159891a3
    let e = hash[4]
    assert e = 0x57d21a90
    let f = hash[5]
    assert f = 0x2c358e6f
    let g = hash[6]
    assert g = 0xeb02f14c
    let h = hash[7]
    assert h = 0xcaf48fcd

    return ()
end