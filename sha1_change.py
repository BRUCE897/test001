# sha1-v1
import struct

bitlen = lambda s: len(s) * 8


def ROL4(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def madd(*args):
    return sum(args) & 0xffffffff


class sha1:
    block_size = 64
    digest_size = 20

    def __init__(self, data=b''):
        if data is None:
            self._buffer = b''
        elif isinstance(data, bytes):
            self._buffer = data
        elif isinstance(data, str):
            self._buffer = data.encode('ascii')
        else:
            raise TypeError('object supporting the buffer API required')

        self._sign = None

    def update(self, content):
        if isinstance(content, bytes):
            self._buffer += content
        elif isinstance(content, str):
            self._buffer += content.encode('ascii')
        else:
            raise TypeError('object supporting the buffer API required')

        self._sign = None

    def copy(self):
        other = self.__class__.__new__(self.__class__)
        other._buffer = self._buffer
        return other

    def hexdigest(self):
        result = self.digest()
        return result.hex()

    def digest(self):
        if not self._sign:
            self._sign = self._current()
        return self._sign

    def _current(self):
        msg = self._buffer

        # standard magic number
        # A = 0x67452301
        # B = 0xEFCDAB89
        # C = 0x98BADCFE
        # D = 0x10325476
        # E = 0xC3D2E1F0

        A = 0x67452301
        B = 0xEFCDAB89
        C = 0x98BADCFE
        D = 0x5E4A1F7C
        E = 0x10325476

        msg_len = bitlen(msg) & 0xffffffffffffffff

        zero_pad = (56 - (len(msg) + 1) % 64) % 64
        msg = msg + b'\x80'
        msg = msg + b'\x00' * zero_pad + struct.pack('>Q', msg_len)

        for idx in range(0, len(msg), 64):
            W = list(struct.unpack('>16I', msg[idx:idx + 64])) + [0] * 64

            for t in range(16, 80):
                T = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
                W[t] = ROL4(T, 1)

            a, b, c, d, e = A, B, C, D, E

            # main loop:
            for t in range(80):
                if t <= 15:
                    k = 0x5a827999
                    f = (b & c) ^ (~b & d)
                elif t <= 19:
                    k = 0x6ed9eba1
                    f = b ^ c ^ d
                elif t <= 39:
                    k = 0x8f1bbcdc
                    f = (b & c) ^ (b & d) ^ (c & d)
                elif t <= 59:
                    k = 0x5a827999
                    f = (b & c) ^ (~b & d)
                else:
                    k = 0xca62c1d6
                    f = b ^ c ^ d

                S0 = madd(ROL4(a, 5), f, e, k, W[t])
                S1 = ROL4(b, 30)

                if t == 79:
                    a, b, d, c, e = S0, a, S1, c, d
                else:
                    a, b, c, d, e = S0, a, S1, c, d

            A = madd(A, a)
            B = madd(B, b)
            C = madd(C, c)
            D = madd(D, d)
            E = madd(E, e)

        result = struct.pack('>5I', A, B, C, D, E)
        return result


if __name__ == '__main__':
    s = b'muyang'
    s0 = sha1(s).hexdigest()
    print(s0)

