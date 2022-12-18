# NULL Pointer Exception

## Overview

As a result of invalid input validation (CWE-233: Improper Handling of Parameters), specific files passed to the command line application, `crasm`, can lead to a NULL pointer dereference (CWE-476: NULL Pointer Dereference) in the function `Xasc`.

## About

`crasm` is a command line utility available on the Ubuntu package manager and [GitHub][crasm-github] which assembles code for the 6800, 6801, 6803, 6502, 65C02, and Z80. At the time of writing, the current version is 1.8-3 on Ubuntu and commit [5471a9f][commit] on GitHub.

## Vulnerability

The `char * oper` parameter in the function `Xasc` is not checked prior to assignment to `s` and then dereferenced and assigned to `delemiter`.

```C
int Xasc(int modifier, char* label, char* mnemo, char* oper)
{
  register char* s;
  register char r;
  register char delimiter;

  s = oper;
  delimiter = *s;
```

The caller function `asmline` also fails to validate input prior to passing control to the callee. The `ptr` member of the `labmnemo` contains the address of the callee function, in this case, `Xasc`.

```c
int asmline(char* s, int status)
...
    if (status & 2)
    {
      (*labmnemo->ptr)(labmnemo->modifier, label, mnemo, oper);
    }
...
```

### Affected versions

- 1.8-3 (as of writing, the current version) available on the Ubuntu package manager.
- Versions compiled from commit `932f3293f96f36bfe32f8d8d70a5ba693d3b3193` and below.

### Minimum Viable Patch

A patch was submitted to the maintainer and merged into the source repository with [merge request #7][https://github.com/colinbourassa/crasm/pull/7] containing the patch below. The version installed with Ubuntu (22.10 and 22.04) remain vulnerable as of writing.

```c
diff --git a/src/pseudos.c b/src/pseudos.c
index a1613ee..802939c 100644
--- a/src/pseudos.c
+++ b/src/pseudos.c
@@ -213,6 +213,11 @@ int Xnam(int modifier, char* label, char* mnemo, char* oper)
 /*  ASC string  */
 int Xasc(int modifier, char* label, char* mnemo, char* oper)
 {
+
+  if (oper == NULL) {
+    error("Need an operand");
+  }
+
   register char* s;
   register char r;
   register char delimiter;
```

### Recommend Common Vulnerability Score

Overall: 1.6
CVSS Base Score: 1.7
Impact Subscore: 1.4
Exploitability Subscore: 0.3

## Validation:

To validate the existence of NULL pointer dereference, use the include test case for cause a segmentation fault. The file is passed in as the first argument to the program.

```shell
# Using apt
$ apt update
$ apt install crasm
$ apt list | grep crasm
crasm/jammy,now 1.8-3 amd64 [installed]

$ crasm /4ed6eacf6ec3c24f587ec3321b5fd739480c96a7679c8108f2f6034f07ecaff4
Pass #1
Segmentation fault

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

./src/crasm /4ed6eacf6ec3c24f587ec3321b5fd739480c96a7679c8108f2f6034f07ecaff4
Pass #1
Segmentation fault
```

### Backtrace

Using `lldb`, observe that `oper` is NULL.

```text
$ lldb -- ./crasm ./4ed6eacf6ec3c24f587ec3321b5fd739480c96a7679c8108f2f6034f07ecaff4
(lldb) run
Process 99307 launched: '/crasm/src/crasm' (x86_64)
Pass #1
Process 99307 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
    frame #0: 0x00000001000037b3 crasm`Xasc(modifier=0, label="msgb", mnemo="asc", oper=0x0000000000000000) at pseudos.c:221:15
   218    register char delimiter;
   219
   220    s = oper;
-> 221    delimiter = *s;
   222
   223    if (delimiter != '\'' && delimiter != '\"')
   224    {
Target 0: (crasm) stopped.
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
  * frame #0: 0x00000001000037b3 crasm`Xasc(modifier=0, label="msgb", mnemo="asc", oper=0x0000000000000000) at pseudos.c:221:15
    frame #1: 0x0000000100002d6c crasm`asmline(s="asc", status=3) at crasm.c:562:7
    frame #2: 0x00000001000027b1 crasm`pass(n=1) at crasm.c:274:9
    frame #3: 0x0000000100002490 crasm`crasm(flag=138) at crasm.c:180:3
    frame #4: 0x0000000100002292 crasm`main(argc=0, argv=0x00007ff7bfeff440) at crasm.c:147:5
    frame #5: 0x00007ff812381310 dyld`start + 2432
```

[crasm-ubuntu]: https://packages.ubuntu.com/kinetic/crasm
[crasm-github]: https://github.com/colinbourassa/crasm
[5471a9f]: https://github.com/colinbourassa/crasm/commit/5471a9f991fa795a1e86568cf5b4433e6c169047