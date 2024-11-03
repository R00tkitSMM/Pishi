# Pishi
Pishi is a static binary rewriting tool designed to instrument `basic blocks` in XNU kernel and in arbitrary macOS kernel extensions (kexts). \
for XNU kernel, Pishi allows you to instrument at a function, file, or folder level. For example, you can instrument everything in the `/bsd/net/` directory or focus specifically on `content_filter.c` or just one specific function in the XNU source code, e.g [`vnode_getfromfd`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/vfs/vfs_syscalls.c#L3934). this enables targeted fuzzing.

After building and installing Pishi, you can use [my modified version of libprotobuf-mutator](https://github.com/R00tkitSMM/libprotobuf-mutator) which requires you to apply [my patch](https://github.com/R00tkitSMM/Pishi/blob/main/fuzz/llvm.patch)( to make libfuzzer Pishi-aware) then build LLVM to have structure-aware, feedback-aware macOS kernel KEXT fuzzing with libFuzzer.

For more technical discussions read [MoreInfo](https://github.com/R00tkitSMM/Pishi/blob/main/MoreInfo.md). and to start fuzzing read [HowToFuzz](https://github.com/R00tkitSMM/Pishi/blob/main/HowToFuzz.md)

compare so other XNU kernel instrumenations methods:
* hardware-assisted, Arm CoreSight instrumenations is no avabilie in Apple silicon.
* kernel.kasan.* do not have Coverage Sanitizer.
* No other public static or dynamic instrumenations methods.


A note on security and safety
Avoid running Pishi on your personal device; instead, use a dedicated research device that you are willing to risk damaging.
