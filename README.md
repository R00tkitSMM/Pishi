# Pishi
Pishi is a static binary rewriting tool designed to instrument the macOS kernel extensions (kexts). \
It includes a code coverage feature similar to Linux kcov.

After building and installing Pishi, you can use [my modified version of libprotobuf-mutator](https://github.com/R00tkitSMM/libprotobuf-mutator) which requires you to apply [my patch](https://github.com/R00tkitSMM/Pishi/blob/main/fuzz/llvm.patch)( to make libfuzzer Pishi-aware) then build LLVM to have structure-aware, feedback-aware macOS kernel KEXT fuzzing with libFuzzer.

For more technical discussions read [MoreInfo](https://github.com/R00tkitSMM/Pishi/blob/main/MoreInfo.md). and to start fuzzing read [HowToFuzz](https://github.com/R00tkitSMM/Pishi/blob/main/HowToFuzz.md)

To-do list:
- [X] Port libprotobuf-mutator to macOS
- [x] Getting BB address in runtine instead of getting it in instrumentation time.
- [X] Revisit BBs( What other BBs can we instument.)
- [X] Instument muliple KEXTs and select which one to be activated.
- [ ] To instrument the kernel at the function, file, or folder level, we can use dSYM files to obtain address ranges (e.g., `[0xfffffe00075ddd54-0xfffffe00075dde68]`) for a function or functions of files. We then label functions by patching the second instruction with a unique number while saving the original instruction. After modifying the kernel files, we build the kernel with these changes. In our instrument.py, we can locate the functions, restore the patched instruction, and start the instrumentation process. This has worked in my tests, but now I need to automate it.
```

(lldb) image lookup -vn flowadv_add_entry
1 match found in /Users/meysam/project/Pishi/kernels/Kernels/kernel.release.vmapple:
        Address: kernel.release.vmapple[0xfffffe00075ddd54] (kernel.release.vmapple.__TEXT_EXEC.__text + 3755348)
        Summary: kernel.release.vmapple`flowadv_add_entry at flowadv.c:161
         Module: file = "/Users/meysam/project/Pishi/kernels/Kernels/kernel.release.vmapple", arch = "arm64e"
    CompileUnit: id = {0x00000190}, file = "/AppleInternal/Library/BuildRoots/08825dc9-0808-11ef-89d0-fe8bc7981bff/Library/Caches/com.apple.xbs/Sources/xnu/bsd/net/flowadv.c", language = "c99"
       Function: id = {0x00bb2d32}, name = "flowadv_add_entry", range = [0xfffffe00075ddd54-0xfffffe00075dde68)
       FuncType: id = {0x00bb2d32}, byte-size = 0, decl = flowadv.c:160, compiler_type = "void (struct flowadv_fcentry *)"
         Blocks: id = {0x00bb2d32}, range = [0xfffffe00075ddd54-0xfffffe00075dde68)
      LineEntry: [0xfffffe00075ddd54-0xfffffe00075ddd6c): /AppleInternal/Library/BuildRoots/08825dc9-0808-11ef-89d0-fe8bc7981bff/Library/Caches/com.apple.xbs/Sources/xnu/bsd/net/flowadv.c:161
         Symbol: id = {0x00004618}, range = [0xfffffe00075ddd54-0xfffffe00075dde68), name="flowadv_add_entry"
       Variable: id = {0x00bb2d47}, name = "fce", type = "flowadv_fcentry *", valid ranges = <block>, location = [0xfffffe00075ddd54, 0xfffffe00075ddd6c) -> DW_OP_reg0 W0, decl = flowadv.c:160

(lldb) 
```

- [ ] Implementing fake copyClientEntitlement
- [ ] Implementing CompareCoverage(memcmp, strcmp,...)
- [ ] Performance: Using is_instrument_needed in repeated patterns to return before caliing push/pop to safe some cpu cycles!
- [ ] Edge coverage.
- [ ] Using Virtualization.Framework to speed up sasmple saving/sharing via shared memory over VirtIO.
- [ ] Refactor/Cleanup the python code.
- [ ] using M1N1 to instrument in el3
- [ ] using coresight to instrumet in hardware pike intel PT
