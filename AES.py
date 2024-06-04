#!/usr/bin/python3

# Copyright (c) 2015 Chas Williams <3chas3@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# A native python implementation of the Advanced Encryption Standard (AES)

class AES:
    _sbox = []      # Substitution-box
    _sbox_inv = []  # Inverse Substitution-box

    _mult_2 = []    # MixColumns coefficients
    _mult_3 = []
    _mult_9 = []
    _mult_11 = []
    _mult_13 = []
    _mult_14 = []

    exp_GF2 = []    # exponentiaton in a GF(2^8)
    log_GF2 = []    # logarithm in a GF(2^8)

    def mul_gf2(a, b):
        ''' multiplication in a GF(2^8) '''
        r = 0

        while a != 0:
            if a & 0x1 != 0:
                r = r ^ b
            t = b & 0x80
            b = (b << 1) & 0xff
            if t != 0:
                b = b ^ 0x1b
            a = (a & 0xff) >> 1

        return r

    # calculate the exponentiation
    GENERATOR = 3
    y = 0x1
    exp_GF2.append(y)
    for i in range(0, 256):
        y = mul_gf2(y, GENERATOR)
        print(y)
        exp_GF2.append(y)

    # calculate logarithm -- inverse of exponentiation
    log_GF2 = [0] * 256
    for i in range(0, 256):
        log_GF2[exp_GF2[i]] = i

    # calculate the Substitution-box
    for i in range(0, 256):
        if i == 0:
            y = 0
        else:
            y = exp_GF2[0xff - log_GF2[i]]

        # affine transformation
        s = y
        for iter in range(0, 4):
            s = ((s << 1) & 0xff) | (s >> 7)
            y = y ^ s
        y = y ^ 0x63

        _sbox.append(y)

    # calculate the Inverse Substitution-box
    _sbox_inv = [0] * 256
    for i in range(0, 256):
        _sbox_inv[_sbox[i]] = i

    # calculate the MixColumns coefficients
    for i in range(0, 256):
        _mult_2.append(mul_gf2(i, 2))
        _mult_3.append(mul_gf2(i, 3))
        _mult_9.append(mul_gf2(i, 9))
        _mult_11.append(mul_gf2(i, 11))
        _mult_13.append(mul_gf2(i, 13))
        _mult_14.append(mul_gf2(i, 14))

    def __init__(self, key=''):
        key = list(key)
        n = len(key)
        if n == 16:
            self._n_rounds = 10
        elif n == 24:
            self._n_rounds = 12
        elif n == 32:
            self._n_rounds = 14
        else:
            raise Exception("key length should be 16, 24 or 32 bytes")

        self.the_key_schedule = self._key_expansion(key)

    def _xor(self, a, b):
        assert len(a) == len(b)
        r = [0] * len(a)
        for i in range(0, len(a)):
            r[i] = a[i] ^ b[i]
        return r

    def _sub_bytes(self, block):
        assert len(block) == 16
        result = [0] * 16
        for i in range(0, 16):
            result[i] = self._sbox[block[i]]
        return result

    def _inv_sub_bytes(self, block):
        assert len(block) == 16
        result = [0] * 16
        for i in range(0, 16):
            result[i] = self._sbox_inv[block[i]]
        return result

    # Unfortunately, the ShiftRows operations is column major which makes
    # this a bit tricky.  See Figure 8 in FIPS-197
    #
    #   1  5  9 13      1  5  9 13
    #   2  6 10 14      6 10 14  2
    #   3  7 11 15     11 15  3  7
    #   4  8 12 16     16  4  8 12

    def _shift_rows(self, block):
        assert len(block) == 16
        return [block[0], block[5], block[10], block[15],
                block[4], block[9], block[14], block[3],
                block[8], block[13], block[2], block[7],
                block[12], block[1], block[6], block[11]]

    def _inv_shift_rows(self, block):
        assert len(block) == 16
        return [block[0], block[13], block[10], block[7],
                block[4], block[1], block[14], block[11],
                block[8], block[5], block[2], block[15],
                block[12], block[9], block[6], block[3]]

    def _mix_columns(self, block):
        assert len(block) == 16

        def mix_columns(a_0, a_1, a_2, a_3):
            ''' AES's MixColumn operation '''
            b_0 = self._mult_2[a_0] ^ self._mult_3[a_1] ^              a_2  ^              a_3
            b_1 =              a_0  ^ self._mult_2[a_1] ^ self._mult_3[a_2] ^              a_3
            b_2 =              a_0  ^              a_1  ^ self._mult_2[a_2] ^ self._mult_3[a_3]
            b_3 = self._mult_3[a_0] ^              a_1  ^              a_2  ^ self._mult_2[a_3]
            return [b_0, b_1, b_2, b_3]

        result = [0] * 16

        for i in range(0, 16, 4):
            a_0 = block[i+0]
            a_1 = block[i+1]
            a_2 = block[i+2]
            a_3 = block[i+3]
            b_0, b_1, b_2, b_3 = mix_columns(a_0, a_1, a_2, a_3)
            result[i+0] = b_0
            result[i+1] = b_1
            result[i+2] = b_2
            result[i+3] = b_3

        return result

    def _inv_mix_columns(self, block):
        assert len(block) == 16

        def inv_mix_columns(a_0, a_1, a_2, a_3):
            ''' The inverse of MixColumsn '''
            b_0 = self._mult_14[a_0] ^ self._mult_11[a_1] ^ self._mult_13[a_2] ^ self._mult_9[a_3]
            b_1 = self._mult_9[a_0] ^ self._mult_14[a_1] ^ self._mult_11[a_2] ^ self._mult_13[a_3]
            b_2 = self._mult_13[a_0] ^ self._mult_9[a_1] ^ self._mult_14[a_2] ^ self._mult_11[a_3]
            b_3 = self._mult_11[a_0] ^ self._mult_13[a_1] ^ self._mult_9[a_2] ^ self._mult_14[a_3]
            return [b_0, b_1, b_2, b_3]

        result = [0] * 16

        for i in range(0, 16, 4):
            a_0 = block[i+0]
            a_1 = block[i+1]
            a_2 = block[i+2]
            a_3 = block[i+3]
            b_0, b_1, b_2, b_3 = inv_mix_columns(a_0, a_1, a_2, a_3)
            result[i+0] = b_0
            result[i+1] = b_1
            result[i+2] = b_2
            result[i+3] = b_3

        return result

    def key_schedule(self):
        ''' Return a byte representation of the key schedule '''
        _key_schedule = []
        for key_schedule in self.the_key_schedule:
            _key_schedule.append(bytes(key_schedule))
        return _key_schedule

    def _key_expansion(self, key):
        def _rcon(i):
            rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
            return [rcon[i], 0, 0, 0]

        def _rot_word(word):
            assert len(word) == 4
            return word[1:4] + word[0:1]

        def _sub_word(word):
            assert len(word) == 4
            return [self._sbox[word[0]], self._sbox[word[1]], self._sbox[word[2]], self._sbox[word[3]]]

        n = len(key)
        if n == 16:
            b = 176
        elif n == 24:
            b = 208
        elif n == 32:
            b = 240
        else:
            raise Exception("key length should be 16, 24 or 32 bytes")

        i = 1
        while len(key) < b:
            t = key[-4:]

            if len(key) % n == 0:
                t = _rot_word(t)
                t = self._xor(_sub_word(t), _rcon(i))
                i = i + 1
            elif n > 24 and len(key) % n == 16:
                t = _sub_word(t)

            key = key + self._xor(t, key[-n:-n + 4])

        key_schedule = []
        for i in range(0, len(key), 16):
            key_schedule.append(key[i:i + 16])
        return key_schedule

    def encrypt_block(self, block):
        assert len(block) == 16

        # Convert to a list of integers.
        block = list(block)

        state = self._xor(block, self.the_key_schedule[0])
        for i in range(1, self._n_rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._xor(state, self.the_key_schedule[i])
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._xor(state, self.the_key_schedule[self._n_rounds])

        return bytes(state)

    def decrypt_block(self, block):
        assert len(block) == 16

        # Convert to a list of integers.
        block = list(block)

        state = self._xor(block, self.the_key_schedule[self._n_rounds])
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        for i in range(self._n_rounds - 1, 0, -1):
            state = self._xor(state, self.the_key_schedule[i])
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
        state = self._xor(state, self.the_key_schedule[0])

        return bytes(state)


if __name__ == "__main__":
    # from FIPS 197, Appendix A Key Expansion Examples

    KEYS = ['2b7e151628aed2a6abf7158809cf4f3c',
            '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
            '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4']

    for key in KEYS:
        print('key:', key)
        engine = AES(key=bytes.fromhex(key))
        for expanded_key in engine.key_schedule():
            print('    ', expanded_key.hex())
        print('')

    # from FIPS 197, Appendix C.1 AES-128

    PLAINTEXT = '00112233445566778899aabbccddeeff'
    KEY = '000102030405060708090a0b0c0d0e0f'
    CIPHERTEXT = '69c4e0d86a7b0430d8cdb78070b4c55a'

    engine = AES(key=bytes.fromhex(KEY))
    print(CIPHERTEXT, engine.encrypt_block(bytes.fromhex(PLAINTEXT)).hex())
    print(PLAINTEXT, engine.decrypt_block(bytes.fromhex(CIPHERTEXT)).hex())

    # from FIPS 197, Appendix C.2 AES-192

    PLAINTEXT = '00112233445566778899aabbccddeeff'
    KEY = '000102030405060708090a0b0c0d0e0f1011121314151617'
    CIPHERTEXT = 'dda97ca4864cdfe06eaf70a0ec0d7191'

    engine = AES(key=bytes.fromhex(KEY))
    print(CIPHERTEXT, engine.encrypt_block(bytes.fromhex(PLAINTEXT)).hex())
    print(PLAINTEXT, engine.decrypt_block(bytes.fromhex(CIPHERTEXT)).hex())

    # from FIPS 197, Appendix C.3 AES-256

    PLAINTEXT = '00112233445566778899aabbccddeeff'
    KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    CIPHERTEXT = '8ea2b7ca516745bfeafc49904b496089'

    engine = AES(key=bytes.fromhex(KEY))
    print(CIPHERTEXT, engine.encrypt_block(bytes.fromhex(PLAINTEXT)).hex())
    print(PLAINTEXT, engine.decrypt_block(bytes.fromhex(CIPHERTEXT)).hex())
