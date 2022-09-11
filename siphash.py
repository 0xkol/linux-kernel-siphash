import struct

def unp64(x):
    return struct.unpack('>Q', x)[0]

def unp64_le(x):
    return struct.unpack('<Q', x)[0]

def p64(x):
    return struct.pack('>Q', x)

def rol64(x, n):
    x = x & ((1 << 64) - 1)
    return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

def add64(x, y):
    return (x + y) & ((1 << 64) - 1)

class _Siphash():
    def _preamble(self, key, len):
        k0, k1 = unp64(key[0:8]), unp64(key[8:16])
        self.v0 = 0x736f6d6570736575 ^ k0
        self.v1 = 0x646f72616e646f6d ^ k1
        self.v2 = 0x6c7967656e657261 ^ k0
        self.v3 = 0x7465646279746573 ^ k1
        self.b = (len << 56) & ((1 << 64) - 1)

    def _sipround(self):
        self.v0 = add64(self.v0, self.v1)
        self.v1 = rol64(self.v1, 13)
        self.v1 ^= self.v0
        self.v0 = rol64(self.v0, 32)

        self.v2 = add64(self.v2, self.v3)
        self.v3 = rol64(self.v3, 16)
        self.v3 ^= self.v2

        self.v0 = add64(self.v0, self.v3)
        self.v3 = rol64(self.v3, 21)
        self.v3 ^= self.v0

        self.v2 = add64(self.v2,self.v1)
        self.v1 = rol64(self.v1, 17)
        self.v1 ^= self.v2
        self.v2 = rol64(self.v2, 32)

    def _postamble(self):
        self.v3 ^= self.b
        self._sipround()
        self._sipround()
        self.v0 ^= self.b
        self.v2 ^= 0xff
        self._sipround()
        self._sipround()
        self._sipround()
        self._sipround()

    def digest(self):
        return p64((self.v0 ^ self.v1) ^ (self.v2 ^ self.v3))
    
    def hexdigest(self):
        return self.digest().hex()

    def siphash_1u64(self, key, first):
        self._preamble(key, 8)

        self.v3 ^= first
        self._sipround()
        self._sipround()
        self.v0 ^= first

        self._postamble()

    def siphash_2u64(self, key, first, second):
        self._preamble(key, 16)

        self.v3 ^= first
        self._sipround()
        self._sipround()
        self.v0 ^= first

        self.v3 ^= second
        self._sipround()
        self._sipround()
        self.v0 ^= second

        self._postamble()

    def siphash_3u64(self, key, first, second, third):
        self._preamble(key, 24)

        self.v3 ^= first
        self._sipround()
        self._sipround()
        self.v0 ^= first

        self.v3 ^= second
        self._sipround()
        self._sipround()
        self.v0 ^= second

        self.v3 ^= third
        self._sipround()
        self._sipround()
        self.v0 ^= third

        self._postamble()

    def siphash_4u64(self, key, first, second, third, forth):
        self._preamble(key, 32)

        self.v3 ^= first
        self._sipround()
        self._sipround()
        self.v0 ^= first

        self.v3 ^= second
        self._sipround()
        self._sipround()
        self.v0 ^= second

        self.v3 ^= third
        self._sipround()
        self._sipround()
        self.v0 ^= third

        self.v3 ^= forth
        self._sipround()
        self._sipround()
        self.v0 ^= forth

        self._postamble()

    def siphash_1u32(self, key, first):
        self._preamble(key, 4)
        self.b |= first
        self._postamble()

    def siphash_3u32(self, key, first, second, third):
        self._preamble(key, 12)
        combined = second << 32 | first
        self.v3 ^= combined
        self._sipround()
        self._sipround()
        self.v0 ^= combined
        self.b |= third
        self._postamble()
    
    def siphash(self, key, data):
        left = len(data) % 8

        self._preamble(key, len(data))
        for i in range(0, len(data)-left, 8):
            m = unp64_le(data[i:i+8])
            self.v3 ^= m
            self._sipround()
            self._sipround()
            self.v0 ^= m
        
        t = 0
        j = 1
        while j <= left:
            t = (t << 8) | data[-j]
            j += 1
        self.b |= t

        self._postamble()


def siphash(key: bytes, data: bytes) -> bytes:
    h = _Siphash()
    h.siphash(key, data)
    return h.digest()

def siphash_1u64(key: bytes, first: int) -> bytes:
    h = _Siphash()
    h.siphash_1u64(key, first)
    return h.digest()

def siphash_2u64(key: bytes, first: int, second: int) -> bytes:
    h = _Siphash()
    h.siphash_2u64(key, first, second)
    return h.digest()

def siphash_3u64(key: bytes, first: int, second: int, third: int) -> bytes:
    h = _Siphash()
    h.siphash_3u64(key, first, second, third)
    return h.digest()

def siphash_4u64(key: bytes, first: int, second: int, third: int, forth: int) -> bytes:
    h = _Siphash()
    h.siphash_4u64(key, first, second, third, forth)
    return h.digest()

def siphash_1u32(key: bytes, first: int) -> bytes:
    h = _Siphash()
    h.siphash_1u32(key, first)
    return h.digest()

def siphash_3u32(key: bytes, first: int, second: int, third: int) -> bytes:
    h = _Siphash()
    h.siphash_3u32(key, first, second, third)
    return h.digest()
