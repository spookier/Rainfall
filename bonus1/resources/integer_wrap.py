#!/usr/bin/env python3

count = -1073741813

print("passes count <= 9:", count <= 9)
print("(count * 4) modulo 2^32:", (count * 4) & 0xffffffff)
