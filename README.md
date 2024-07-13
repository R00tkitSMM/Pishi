# Pishi
Pishi is a static binary rewriting tool designed to instrument arbitrary macOS kernel extensions (kexts). \
and XNU kernel. for kernel, Pishi allows you to instrument at the function, file, or folder level. For example, you can instrument everything in the `/bsd/net/` directory or focus specifically on `content_filter.c`

After building and installing Pishi, you can use [my modified version of libprotobuf-mutator](https://github.com/R00tkitSMM/libprotobuf-mutator) which requires you to apply [my patch](https://github.com/R00tkitSMM/Pishi/blob/main/fuzz/llvm.patch)( to make libfuzzer Pishi-aware) then build LLVM to have structure-aware, feedback-aware macOS kernel KEXT fuzzing with libFuzzer.

For more technical discussions read [MoreInfo](https://github.com/R00tkitSMM/Pishi/blob/main/MoreInfo.md). and to start fuzzing read [HowToFuzz](https://github.com/R00tkitSMM/Pishi/blob/main/HowToFuzz.md)

To-do list:
- [X] Port libprotobuf-mutator to macOS
- [x] Getting BB address in runtine instead of getting it in instrumentation time.
- [X] Revisit BBs( What other BBs can we instument.)
- [X] Instument muliple KEXTs and select which one to be activated.
- [X] To instrument the kernel at the function, file, or folder level. to instrument kernel we have to let Ghidra analyze everything.

- [ ] Implementing fake copyClientEntitlement
- [ ] Implementing CompareCoverage(memcmp, strcmp,...)
- [ ] Performance: Using is_instrument_needed in repeated patterns to return before caliing push/pop to safe some cpu cycles!
- [ ] Edge coverage.
- [ ] Using Virtualization.Framework to speed up sasmple saving/sharing via shared memory over VirtIO.
- [ ] Refactor/Cleanup the python code.
- [ ] using M1N1 to instrument in el3
- [ ] using coresight to instrumet in hardware pike intel PT
