# Pishi
Pishi is a static binary rewriting tool designed to instrument the macOS kernel extensions (kexts). \
It includes a code coverage feature similar to Linux kcov.

After building and installing Pishi, you can use [my modified version of libprotobuf-mutator](https://github.com/R00tkitSMM/libprotobuf-mutator) to enable structure-aware, feedback-aware macOS kernel KEXT fuzzing with libFuzzer.

For more technical discussions read [MoreInfo](https://github.com/R00tkitSMM/Pishi/blob/main/MoreInfo.md). and to start fuzzing read [HowToFuzz](https://github.com/R00tkitSMM/Pishi/blob/main/HowToFuzz.md)

To-do list:
- [X] Port libprotobuf-mutator to macOS
- [x] Getting BB address in runtine instead of getting it in instrumentation time.
- [X] Revisit BBs( What other BBs can we instument.)
- [ ] Instument muliple KEXTs and select which one to be activated. 
```
inline uint64_t setFlag(uint64_t flags, int pos) {
    return flags | (1UL << pos);
}

// Inline function to clear a flag at a specific position
inline uint64_t clearFlag(uint64_t flags, int pos) {
    return flags & ~(1UL << pos);
}

// Inline function to check if a flag is set at a specific position
inline bool isFlagSet(uint64_t flags, int pos) {
    return flags & (1UL << pos);
}

call isFlagSet afer  if ( __improbable(do_instrument) )
have IOCTL to set or clear flags. one flag for each KEXT. so set 2 means instrumet this two. or instument just this one.
```
- [ ] Implementing fake copyClientEntitlement
- [ ] Implementing CompareCoverage(memcmp, strcmp,...)
- [ ] Instrumenting kernel itself.
- [ ] Performance: Using is_instrument_needed in repeated patterns to return before caliing push/pop to safe some cpu cycles!
- [ ] Edge coverage.
- [ ] Using Virtualization.Framework to speed up sasmple saving/sharing via shared memory over VirtIO.
