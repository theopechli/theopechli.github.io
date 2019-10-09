---
layout: post
title:  "Welcome to Phoenix!"
date:   2019-10-09 22:00:00 +0300
categories: reverse-engineering binary-exploitation exploit-education exploit-education-phoenix
---
Phoenix is a virtual machine that can be obtained from [exploit.education][exploit-education]. It provides an educational environment so that one can practice on their skills. For additional details, visit the website.

In case of reluctancy due to the risk of downloading an unknown virtual machine, Debian packages are also provided.

Stack Zero, which is the first level, introduces the legendary stack-based buffer overflow.

In order to get a glimpse of what the binary is all about, [rabin2][rabin2-docs] comes to the rescue:

{% highlight plaintext %}
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

[exploit-education]: https://exploit.education/downloads/
[rabin2-docs]: https://r2wiki.readthedocs.io/en/latest/tools/rabin2/
