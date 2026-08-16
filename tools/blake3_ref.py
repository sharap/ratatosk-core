"""Референсная реализация BLAKE3 на Python — только для генерации векторов.

Нужна ровно затем, чтобы ожидаемые значения считались НЕ тем кодом, который
они проверяют. Совпадение Rust-реализации с этой означает совместимость двух
независимых реализаций; совпадение кода с самим собой не означает ничего.

Корректность самой этой реализации проверяется официальными контрольными
векторами BLAKE3 (см. selftest()).
"""

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

MASK = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr(state[b] ^ state[c], 7)


def round_fn(state, m):
    g(state, 0, 4, 8, 12, m[0], m[1])
    g(state, 1, 5, 9, 13, m[2], m[3])
    g(state, 2, 6, 10, 14, m[4], m[5])
    g(state, 3, 7, 11, 15, m[6], m[7])
    g(state, 0, 5, 10, 15, m[8], m[9])
    g(state, 1, 6, 11, 12, m[10], m[11])
    g(state, 2, 7, 8, 13, m[12], m[13])
    g(state, 3, 4, 9, 14, m[14], m[15])


def permute(m):
    return [m[MSG_PERMUTATION[i]] for i in range(16)]


def compress(cv, block_words, counter, block_len, flags):
    state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK, (counter >> 32) & MASK, block_len, flags,
    ]
    block = list(block_words)
    for _ in range(6):
        round_fn(state, block)
        block = permute(block)
    round_fn(state, block)
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def words_from_le(b):
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


class Output:
    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv = cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return compress(self.cv, self.block_words, self.counter,
                        self.block_len, self.flags)[:8]

    def root_output_bytes(self, length):
        out = bytearray()
        counter = 0
        while len(out) < length:
            words = compress(self.cv, self.block_words, counter,
                             self.block_len, self.flags | ROOT)
            for w in words:
                out.extend(w.to_bytes(4, "little"))
            counter += 1
        return bytes(out[:length])


class ChunkState:
    def __init__(self, key_words, chunk_counter, flags):
        self.cv = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self):
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def start_flag(self):
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data):
        while data:
            if self.block_len == BLOCK_LEN:
                self.cv = compress(self.cv, words_from_le(self.block),
                                   self.chunk_counter, BLOCK_LEN,
                                   self.flags | self.start_flag())[:8]
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0
            take = min(BLOCK_LEN - self.block_len, len(data))
            self.block[self.block_len:self.block_len + take] = data[:take]
            self.block_len += take
            data = data[take:]

    def output(self):
        return Output(self.cv, words_from_le(self.block), self.chunk_counter,
                      self.block_len,
                      self.flags | self.start_flag() | CHUNK_END)


def parent_output(left_cv, right_cv, key_words, flags):
    return Output(list(key_words), left_cv + right_cv, 0, BLOCK_LEN,
                  PARENT | flags)


class Hasher:
    def __init__(self, key_words, flags):
        self.chunk_state = ChunkState(key_words, 0, flags)
        self.key_words = list(key_words)
        self.cv_stack = []
        self.flags = flags

    @classmethod
    def new(cls):
        return cls(IV, 0)

    @classmethod
    def new_keyed(cls, key):
        assert len(key) == KEY_LEN
        return cls(words_from_le(key), KEYED_HASH)

    @classmethod
    def new_derive_key(cls, context):
        ctx = cls(IV, DERIVE_KEY_CONTEXT)
        ctx.update(context.encode("utf-8"))
        return cls(words_from_le(ctx.finalize(KEY_LEN)), DERIVE_KEY_MATERIAL)

    def add_chunk_cv(self, new_cv, total_chunks):
        while total_chunks & 1 == 0:
            new_cv = parent_output(self.cv_stack.pop(), new_cv,
                                   self.key_words, self.flags).chaining_value()
            total_chunks >>= 1
        self.cv_stack.append(new_cv)

    def update(self, data):
        while data:
            if self.chunk_state.length() == CHUNK_LEN:
                cv = self.chunk_state.output().chaining_value()
                total = self.chunk_state.chunk_counter + 1
                self.add_chunk_cv(cv, total)
                self.chunk_state = ChunkState(self.key_words, total, self.flags)
            take = min(CHUNK_LEN - self.chunk_state.length(), len(data))
            self.chunk_state.update(data[:take])
            data = data[take:]

    def finalize(self, length=OUT_LEN):
        output = self.chunk_state.output()
        remaining = len(self.cv_stack)
        while remaining > 0:
            remaining -= 1
            output = parent_output(self.cv_stack[remaining],
                                   output.chaining_value(),
                                   self.key_words, self.flags)
        return output.root_output_bytes(length)


def hash_(data, length=OUT_LEN):
    h = Hasher.new()
    h.update(data)
    return h.finalize(length)


def keyed_hash(key, data, length=OUT_LEN):
    h = Hasher.new_keyed(key)
    h.update(data)
    return h.finalize(length)


def derive_key(context, material, length=OUT_LEN):
    h = Hasher.new_derive_key(context)
    h.update(material)
    return h.finalize(length)


# --- проверка официальными контрольными векторами BLAKE3 --------------------

OFFICIAL_KEY = b"whats the Elvish word for friend"
OFFICIAL_CONTEXT = "BLAKE3 2019-12-27 16:29:52 test vectors context"

# Вход по правилу официального набора: повторяющаяся последовательность
# 0, 1, ..., 250, 0, 1, ...
def official_input(n):
    return bytes(i % 251 for i in range(n))


# Сверяются первые 60 hex-символов: источник, из которого векторы получены,
# местами терял последний символ, а 30 байт совпадения исключают случайность.
OFFICIAL_CASES = [
    (0,
     "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f326",
     "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d2",
     "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
    (1,
     "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
     "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
     "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
    (2,
     "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee6",
     "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
     "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
    # Длиннее одного чанка (1024 байта) — задействуют дерево и родительские
    # узлы. Без них совпадение на коротких входах ничего не говорит о том,
    # правильно ли собран стек цепочек.
    (1025,
     "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b844",
     "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea6",
     "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
    (2049,
     "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303",
     "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
     "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
]

PREFIX = 60


def selftest():
    ok = True
    for n, want_hash, want_keyed, want_derive in OFFICIAL_CASES:
        data = official_input(n)
        got_hash = hash_(data, 131).hex()
        got_keyed = keyed_hash(OFFICIAL_KEY, data, 131).hex()
        got_derive = derive_key(OFFICIAL_CONTEXT, data, 131).hex()
        for name, got, want in (("hash", got_hash, want_hash),
                                ("keyed_hash", got_keyed, want_keyed),
                                ("derive_key", got_derive, want_derive)):
            k = min(PREFIX, len(want))
            if got[:k] != want[:k]:
                ok = False
                print(f"РАСХОЖДЕНИЕ len={n} {name}\n  ожидалось {want[:k]}\n  получено  {got[:k]}")
    return ok


if __name__ == "__main__":
    print("самопроверка по официальным векторам BLAKE3:",
          "пройдена" if selftest() else "ПРОВАЛЕНА")
