#!/usr/bin/python3

# This takes about 0.7s on my laptop, so roughly 230KB/s.

from AES import AES
import time

key_128 = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
block = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')

NUM_BLOCKS = 10000

engine = AES(key=key_128)
start = time.time()
for _ in range(0, NUM_BLOCKS):
    engine.encrypt_block(block)
end = time.time()

rate = NUM_BLOCKS * len(block) / (end - start)
print(rate / 1024.0, 'KB/sec')
