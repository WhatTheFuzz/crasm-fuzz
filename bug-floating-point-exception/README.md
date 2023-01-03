# Floating Point Exception

## Overview

As a result of invalid input validation (CWE-233: Improper Handling of Parameters), specific files passed to the command line application, `crasm`, can lead to a divide by zero fault (CWE-369: Divide By Zero) in the function `opdiv`.

## About

`crasm` is a command line utility available on the Ubuntu package manager and [GitHub][crasm-github] which assembles code for the 6800, 6801, 6803, 6502, 65C02, and Z80. At the time of writing, the current version is 1.8-3 on Ubuntu and commit [5471a9f][5471a9f] on GitHub.

## Vulnerability

The parameter `presult` and it's members are not checked prior to a division operation. As a result a floating point exception will occur with `value` is zero and subsequently divided by itself.

```C
void opdiv(struct result* presult, struct result* parg)
{
  presult->flags |= parg->flags;
  checktype(presult, L_ABSOLUTE);
  checktype(parg, L_ABSOLUTE);
  presult->value /= parg->value;
}
```

### Affected versions

- 1.8-3 (as of writing, the current version) available on the Ubuntu package manager.
- Versions compiled from commit `932f3293f96f36bfe32f8d8d70a5ba693d3b3193` and below.

### Minimum Viable Patch

A patch was submitted to the maintainer and merged into the source repository with [merge request #7][crasm-pr] containing the patch below. The version installed with Ubuntu (22.10 and 22.04) remain vulnerable as of writing.

```c
diff --git a/src/operator.c b/src/operator.c
index a28ac88..e589756 100644
--- a/src/operator.c
+++ b/src/operator.c
@@ -412,7 +412,10 @@ void opdiv(struct result* presult, struct result* parg)
   presult->flags |= parg->flags;
   checktype(presult, L_ABSOLUTE);
   checktype(parg, L_ABSOLUTE);
-  presult->value /= parg->value;
+  if (parg->value != 0)
+  {
+    presult->value /= parg->value;
+  }
 }

 void oprlist(struct result* presult, struct result* parg)
```

### Recommended Common Vulnerability Score

- Overall: 1.6
  - CVSS Base Score: 1.7
  - Impact Subscore: 1.4
  - Exploitability Subscore: 0.3

## Validation:

To validate the existence of the floating point exception, use the include test case to cause a fault. The file is passed in as the first argument to the program.

```shell
$ lsb_release -rd
Description:    Ubuntu 22.04.1 LTS
Release:        22.04

# Using apt
$ apt update
$ apt install crasm
$ apt list | grep crasm
crasm/jammy,now 1.8-3 amd64 [installed]

$ crasm /517d1b402d585fdb0458f96802a616419b9112bdc119a2393c35e034576a0c62
Pass #1
Floating point exception

# Using git
$ apt install git make clang
$ git clone https://github.com/colinbourassa/crasm.git
$ cd crasm
$ git checkout 932f3293f96f36bfe32f8d8d70a5ba693d3b3193
$ CC=clang make
8 warnings generated.
clang -O -Wall   -c -o cpuz80.o cpuz80.c
clang -O -Wall  -o crasm crasm.o stdvocabulary.o pseudos.o macro.o label.o parse.o filter.o operator.o output.o xref.o scode.o cpulist.o cpu6800.o cpu6502.o cpuz80.o -lm
done
make[1]: Leaving directory '/crasm/src'

./src/crasm /517d1b402d585fdb0458f96802a616419b9112bdc119a2393c35e034576a0c62
Pass #1
Floating point exception
```

### Backtrace

Observe the exception with `lldb`'s backtrace.

```text
$ lldb -- ./crasm ./517d1b402d585fdb0458f96802a616419b9112bdc119a2393c35e034576a0c62
(lldb) target create "./crasm"
Current executable set to '/crasm/src/crasm' (x86_64).
(lldb) settings set -- target.run-args  "./517d1b402d585fdb0458f96802a616419b9112bdc119a2393c35e034576a0c62"
(lldb) r
Process 2564 launched: '/crasm/src/crasm' (x86_64)
Pass #1
Process 2564 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_ARITHMETIC (code=EXC_I386_DIV, subcode=0x0)
    frame #0: 0x00000001000078f4 crasm`opdiv(presult=0x0000000100017468, parg=0x00007ff7bfefefa0) at operator.c:415:18
   412    presult->flags |= parg->flags;
   413    checktype(presult, L_ABSOLUTE);
   414    checktype(parg, L_ABSOLUTE);
-> 415    presult->value /= parg->value;
   416  }
   417
   418  void oprlist(struct result* presult, struct result* parg)
Target 0: (crasm) stopped.
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_ARITHMETIC (code=EXC_I386_DIV, subcode=0x0)
  * frame #0: 0x00000001000078f4 crasm`opdiv(presult=0x0000000100017468, parg=0x00007ff7bfefefa0) at operator.c:415:18
    frame #1: 0x0000000100006455 crasm`parse2(expr="ed/maica", presult=0x0000000100017468) at parse.c:152:7
    frame #2: 0x00000001000062b4 crasm`parse(expr="ed/maica") at parse.c:233:3
    frame #3: 0x0000000100009357 crasm`findmode(oper="aciam/de", pvalue=0x00007ff7bfeff068) at cpu6800.c:99:11
    frame #4: 0x0000000100009214 crasm`standard(code=202, label=0x0000000000000000, mnemo="orab", oper="aciam/de") at cpu6800.c:163:9
    frame #5: 0x0000000100002d3c crasm`asmline(s="orab aciam/de", status=3) at crasm.c:562:7
    frame #6: 0x0000000100002781 crasm`pass(n=1) at crasm.c:274:9
    frame #7: 0x0000000100002460 crasm`crasm(flag=138) at crasm.c:180:3
    frame #8: 0x0000000100002262 crasm`main(argc=0, argv=0x00007ff7bfeff440) at crasm.c:147:5
    frame #9: 0x00007ff812381310 dyld`start + 2432
```

[crasm-ubuntu]: https://packages.ubuntu.com/kinetic/crasm
[crasm-github]: https://github.com/colinbourassa/crasm
[5471a9f]: https://github.com/colinbourassa/crasm/commit/5471a9f991fa795a1e86568cf5b4433e6c169047