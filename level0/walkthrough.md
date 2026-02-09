## Phase 1: Reconnaissance

We list the home directory and locate the binary for this level:

```console
ls -la
```

A binary named level0 is present

To analyze it properly on our host machine, we copy it from the VM:

```console
scp -P 4242 level0@IP_TO_VM:level0 .
```

## Phase 2: Static Analysis

We load the binary into **Ghidra** and analyze it

While reviewing the decompiled code, we observe that the program accesses `argv[1]` and performs a comparison against a hardcoded value

If the condition matches, it spawns a shell

```c
if (atoi(argv[1]) == 423)
{
    execv("/bin/sh", ...);
}
```

## Phase 3: Triggering the Shell

We run the program using the required value:

```console
./level0 423
```

A shell is spawned. We confirm which user the shell runs as:

```console
whoami
level1
```

So the binary effectively grants us a shell with level1 privileges when the argument check succeeds

## Phase 4: Retrieving the Next Password

The subject states that each level’s password is stored in the next user’s home directory in a .pass file

Now that we are level1, we read:
```console
cat /home/user/level1/.pass
```

This reveals the password (flag) for level1, allowing us to log in and proceed to the next level
