
### what do Pishi do
Pishi only instruments basic blocks (BBs) that contain at least one non-relative instruction. In my analysis, this includes almost every necessary BB. The remaining blocks are those containing only a "B" instruction and its sub-instructions.

After checking LibFuzzer with different code bases using the `-fsanitize=address` flag and using Ghidra to inspect the instrumentation, I can confirm that LibFuzzer also does not instrument basic blocks without non-relative instructions.
You can instrument your code with `-fsanitize-coverage=bb,no-prune,trace-pc-guard` or `-fsanitize-coverage=no-prune,trace-pc-guard` to cover every edge. However, the fuzzer does not utilize this instrumentation.

What LibFuzzer asserts to be edge coverage is actually a BB coverage, [ColLAFL](https://wcventure.github.io/FuzzingPaper/Paper/SP18_ColLAFL.pdf)
```
Given edge coverage, we could of course infer block coverage. In some cases, we could even infer edge coverage from
block coverage. SanitizerCoverage further removes critical
edges to secure the latter inference4
, and claim to support
edge coverage. But it is just an enhanced version of block
coverage. Block coverage provides fewer information than
edge coverage. Critical edge is just one factor that hinders
inferring edge coverage from block coverage. 
```

For example
``` 
// sample.c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 9 && data[0] == 'M')
        if (data[1] == 'E')
            if (data[2] == 'Y')
                if (data[3] == 'S')
                    if (data[4] == 'A')
                        if (data[5] == 'M')
                            if (data[6] == '6')
                                if (data[7] == '7')
                                    if (data[8] == '8')
                                        if (data[9] == '9') {
                                            int* p = (int*)0x41414141;
                                            *p = 0x42424242;
                                        }
    return 0;
}
```

compile above code with `clang -fsanitize=address,fuzzer sample.c`

the llvm does not instument BBs with only one 'B' instruction. 
```
undefined8 LLVMFuzzerTestOneInput(char *param_1,ulong param_2)

{
  int iVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  
  __TMC_END__ = __TMC_END__ + '\x01';
  __sanitizer_cov_trace_const_cmp8(9);
  if (param_2 < 10) {
    DAT_00250f61 = DAT_00250f61 + '\x01';
  }
  else {
    cVar3 = *((param_1 >> 3) + 0x1000000000);
    if ((cVar3 != '\0') && (iVar1 = param_1 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)
       ) {
      __asan_report_load1(iVar4,param_1);
    }
    cVar3 = *param_1;
    __sanitizer_cov_trace_const_cmp4(0x4d);
    if (cVar3 == 'M') {
      pcVar2 = param_1 + 1;
      cVar3 = *((pcVar2 >> 3) + 0x1000000000);
      if ((cVar3 != '\0') &&
         (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
        __asan_report_load1(iVar4,pcVar2);
      }
      cVar3 = param_1[1];
      __sanitizer_cov_trace_const_cmp4(0x45);
      if (cVar3 == 'E') {
        pcVar2 = param_1 + 2;
        cVar3 = *((pcVar2 >> 3) + 0x1000000000);
        if ((cVar3 != '\0') &&
           (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
          __asan_report_load1(iVar4,pcVar2);
        }
        cVar3 = param_1[2];
        __sanitizer_cov_trace_const_cmp4(0x59);
        if (cVar3 == 'Y') {
          pcVar2 = param_1 + 3;
          cVar3 = *((pcVar2 >> 3) + 0x1000000000);
          if ((cVar3 != '\0') &&
             (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
            __asan_report_load1(iVar4,pcVar2);
          }
          cVar3 = param_1[3];
          __sanitizer_cov_trace_const_cmp4(0x53);
          if (cVar3 == 'S') {
            pcVar2 = param_1 + 4;
            cVar3 = *((pcVar2 >> 3) + 0x1000000000);
            if ((cVar3 != '\0') &&
               (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
              __asan_report_load1(iVar4,pcVar2);
            }
            cVar3 = param_1[4];
            __sanitizer_cov_trace_const_cmp4(0x41);
            if (cVar3 == 'A') {
              pcVar2 = param_1 + 5;
              cVar3 = *((pcVar2 >> 3) + 0x1000000000);
              if ((cVar3 != '\0') &&
                 (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
                __asan_report_load1(iVar4,pcVar2);
              }
              cVar3 = param_1[5];
              __sanitizer_cov_trace_const_cmp4(0x4d);
              if (cVar3 == 'M') {
                pcVar2 = param_1 + 6;
                cVar3 = *((pcVar2 >> 3) + 0x1000000000);
                if ((cVar3 != '\0') &&
                   (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
                  __asan_report_load1(iVar4,pcVar2);
                }
                cVar3 = param_1[6];
                __sanitizer_cov_trace_const_cmp4(0x36);
                if (cVar3 == '6') {
                  pcVar2 = param_1 + 7;
                  cVar3 = *((pcVar2 >> 3) + 0x1000000000);
                  if ((cVar3 != '\0') &&
                     (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
                    __asan_report_load1(iVar4,pcVar2);
                  }
                  cVar3 = param_1[7];
                  __sanitizer_cov_trace_const_cmp4(0x37);
                  if (cVar3 == '7') {
                    pcVar2 = param_1 + 8;
                    cVar3 = *((pcVar2 >> 3) + 0x1000000000);
                    if ((cVar3 != '\0') &&
                       (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
                      __asan_report_load1(iVar4,pcVar2);
                    }
                    cVar3 = param_1[8];
                    __sanitizer_cov_trace_const_cmp4(0x38);
                    if (cVar3 == '8') {
                      pcVar2 = param_1 + 9;
                      cVar3 = *((pcVar2 >> 3) + 0x1000000000);
                      if ((cVar3 != '\0') &&
                         (iVar1 = pcVar2 & 7, iVar4 = cVar3 - iVar1, iVar4 == 0 || cVar3 < iVar1)) {
                        __asan_report_load1(iVar4,pcVar2);
                      }
                      cVar3 = param_1[9];
                      __sanitizer_cov_trace_const_cmp4(0x39);
                      if (cVar3 == '9') {
                        DAT_00250f6c = DAT_00250f6c + '\x01';
                        if ((DAT_1008282828 != '\0') &&
                           (iVar1 = DAT_1008282828 + -4, iVar1 == 0 || DAT_1008282828 < 4)) {
                          __asan_report_store4(iVar1,&DAT_41414141);
                        }
                        _DAT_41414141 = 0x42424242;
                      }
                      else {
                        DAT_00250f6b = DAT_00250f6b + '\x01';
                      }
                    }
                    else {
                      DAT_00250f6a = DAT_00250f6a + '\x01';
                    }
                  }
                  else {
                    DAT_00250f69 = DAT_00250f69 + '\x01';
                  }
                }
                else {
                  DAT_00250f68 = DAT_00250f68 + '\x01';
                }
              }
              else {
                DAT_00250f67 = DAT_00250f67 + '\x01';
              }
            }
            else {
              DAT_00250f66 = DAT_00250f66 + '\x01';
            }
          }
          else {
            DAT_00250f65 = DAT_00250f65 + '\x01';
          }
        }
        else {
          DAT_00250f64 = DAT_00250f64 + '\x01';
        }
      }
      else {
        DAT_00250f63 = DAT_00250f63 + '\x01';
      }
    }
    else {
      DAT_00250f62 = DAT_00250f62 + '\x01';
    }
  }
  return 0;
}

```
### instument more BBS

After listing all basic blocks and filtering out those containing at least one instruction that we can instrument in all macOS KEXTs and kernel, we find that the remaining basic blocks contain at least one of the following instructions.

TODO: check which one is non-relative instuction and add it to the instument.py so we can instument them too.
```
set(['smull2', 'sqadd', 'sdiv', 'fcvtzs', 'fcvtzu', 'fcmp', 'stlrb', 'pacia1716', 'fcvt', 'brk', 'fminv',
'b.hi', 'aesmc', 'ldeorh', 'smax', 'b.pl', 'madd', 'fmaxv', 'csinv', 'fsub', 'pacibsp', 'ldclrh', 'ldeorb',
'smstop', 'smaddl', 'clz', 'cset', 'fnmsub', 'csel', 'clrex', 'swpal', 'ldxr', 'xpaci', 'b.cc', 'fmaxnm',
'fdiv', 'cbnz', 'xpacd', 'umov', 'bl', 'fmla', 'b.cs', 'fadd', 'bti', 'umaddl', 'yield', 'fneg', 'aese',
'sqxtn', 'braa', 'extr', 'b', 'fabs', 'rbit', 'mrs', 'srshl', 'sqxtn2', 'wfe', 'isb', 'smlal', 'wfi', 'pacia',
'rev16', 'b.mi', 'ucvtf', 'csetm', 'tlbi', 'ldapr', 'tbnz', 'adrp', 'msr', 'ldclr', 'stlr', 'b.vc', 'b.eq',
'frinta', 'ldar', 'scvtf', 'smull', 'ret', 'frinti', 'rev', 'fccmp', 'bfm', 'b.le', 'fmadd', 'frintp', 'frintm',
'fmul', 'ldeor', 'fcsel', 'frintz', 'dsb', 'frintx', 'cinc', 'udf', 'ld1', 'b.lt', 'smlal2', 'b.ls', 'fmls',
'smstart', 'tbl', 'csinc', 'b.ge', 'sys', 'tbz', 'nop', 'b.gt', 'pacda', 'paciza', 'b.vs', 'sbfiz', 'ld1r',
'ldaprb', 'b.ne', 'st1', 'ubfiz', 'retab', 'ldclral', 'dmb', 'ldarb', 'cbz', 'dup'])
```

###  performance 
we can use following code to skipp lots of instrctions, and check if _is_instrument_needed a way before executing pushs/pops

```

void is_instrument_needed () {
    asm volatile (
                  "ldr x0, [%0]\n"
                  :
                  : "r"(&do_instrument)
                  : "x0", "memory"
         );
}

void instrument_thunks()
{
    volatile asm (
                  ".rept 100000\n"                  // Repeat the following block many times
                  "    STP x0, x30, [sp, #-16]!\n"     // save LR. we can't restore it in pop_regs. as we have jumped here.
                  "    STR x8, [sp, #-8]!\n"
                  "    bl _is_instrument_needed\n"
                  "    cmp x0, #0\n"
                  "    beq 1f\n"
                  "    bl _push_regs\n"
                  "    mov x0, #0x4141\n"           // fix the correct numner when instrumenting as arg0.
                  "    mov x0, #0x4141\n"
                  "    mov x0, #0x4141\n"
                  "    mov x0, #0x4141\n"
                  "    bl _sanitizer_cov_trace_pc\n"
                  "    bl _pop_regs\n"
                  "1:\n"
                  "    LDR x8, [sp], #8\n"
                  "    ldp x0, x30, [sp], #16\n"       // restore LR
                  "    nop\n"
                  "    nop\n"
                  ".endr\n"                         // End of repetition
                  );
}
```

* https://nickdesaulniers.github.io/blog/2023/01/27/critical-edge-splitting/
* https://events.static.linuxfound.org/sites/events/files/slides/AFL%20filesystem%20fuzzing%2C%20Vault%202016_0.pdf
* https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf
* https://dl.acm.org/doi/abs/10.1145/3548606.3560602
* https://www.usenix.org/system/files/sec24fall-prepub-921-schilling.pdf
* https://rev.ng/downloads/iccst-18-paper.pdf
* https://www.usenix.org/conference/usenixsecurity23/presentation/yin
* https://www.usenix.org/system/files/usenixsecurity23-di-bartolomeo.pdf
* https://mboehme.github.io/paper/ICSE22.pdf
* https://qbdi.readthedocs.io/en/stable/intro.html
* https://dl.acm.org/doi/pdf/10.1145/3468264.3473932
* https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf
* https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-2_Aschermann_paper.pdf
* https://www.usenix.org/system/files/sec19-lyu.pdf
* https://arxiv.org/pdf/2209.03441
* https://nebelwelt.net/publications/files/20Oakland.pdf
* https://users.cs.utah.edu/~snagy/papers/19SP.pdf
* https://agra.informatik.uni-bremen.de/doc/konf/FDL2022_nbruns.pdf
* https://users.cs.utah.edu/~snagy/papers/21CCS.pdf


