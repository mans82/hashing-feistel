from hashlib import md5
from typing import Sequence

# User modifiable constants
BLOCKSIZE = 256  # MAX 256
ROUNDS = 8  # MAX 128

# DO NOT MODIFY
KEYLEN = 128


def feistel_round(key: bytes, right_half: bytes) -> bytes:
    return md5(key + right_half, usedforsecurity=True).digest()


def rotate_byte_array(byte_array: bytes, n: int) -> bytes:
    return byte_array[n:] + byte_array[:n]


def feistel_subkeys(round_i: int, main_key: bytes) -> bytes:
    rotated_key = rotate_byte_array(main_key, round_i * (KEYLEN // ROUNDS))
    return md5(rotated_key, usedforsecurity=True).digest()


def bytearray_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def feistel_block_operate(plaintext_block: bytes, key: bytes, round_sequence: Sequence[int]) -> bytes:
    assert len(key) == KEYLEN // 8
    assert len(plaintext_block) == BLOCKSIZE // 8

    left_half, right_half = plaintext_block[:BLOCKSIZE //
                                            16], plaintext_block[BLOCKSIZE // 16:]
    for i in round_sequence:
        subkey = feistel_subkeys(i, key)
        left_half, right_half = right_half, bytearray_xor(
            left_half, feistel_round(subkey, right_half))

    return right_half + left_half


def feistel_encrypt_block(plaintext_block: bytes, key: bytes) -> bytes:
    return feistel_block_operate(plaintext_block, key, range(ROUNDS))


def feistel_decrypt_block(ciphertext_block: bytes, key: bytes) -> bytes:
    return feistel_block_operate(ciphertext_block, key, range(ROUNDS - 1, -1, -1))


def feistel_encrypt(plaintext: bytes, key: bytes) -> bytes:
    assert len(key) == KEYLEN // 8
    assert len(plaintext) % (BLOCKSIZE // 8) == 0

    ciphertext = b''
    for i in range(0, len(plaintext), BLOCKSIZE // 8):
        ciphertext += feistel_encrypt_block(
            plaintext[i:i + BLOCKSIZE // 8], key)

    return ciphertext


def feistel_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    assert len(key) == KEYLEN // 8
    assert len(ciphertext) % (BLOCKSIZE // 8) == 0

    plaintext = b''
    for i in range(0, len(ciphertext), BLOCKSIZE // 8):
        plaintext += feistel_decrypt_block(
            ciphertext[i:i + BLOCKSIZE // 8], key)

    return plaintext


def main():
    key = md5(b'key', usedforsecurity=True).digest()
    plaintext = input(
        'Enter 256bit aligned plaintext (leave blank for a default): ') or '32ByteLongSequenceOfCharsAsPlain'
    plaintext = plaintext.encode('ascii')

    print()
    print(' ==> Plaintext:      ', plaintext)
    ciphertext = feistel_encrypt(plaintext, key)
    print(' ==> Encrypted:      ', ciphertext)
    print(' ==> Encrypted (hex):', ciphertext.hex())
    print(' ==> Decrypted:      ', feistel_decrypt(ciphertext, key))


if __name__ == '__main__':
    main()
