# Pishi
Pishi is a static binary rewriting tool designed to instrument the macOS kernel extensions (kexts). \
It includes a code coverage feature similar to Linux kcov.

After building and installing Pishi, you can use [my modified version of libprotobuf-mutator](https://github.com/R00tkitSMM/libprotobuf-mutator) to enable structure-aware, feedback-aware macOS kernel KEXT fuzzing with libFuzzer.

To-do list:
- [X] Port libprotobuf-mutator to macOS
- [x] Getting BB address in runtine instead of getting it in instrumentation time.
- [ ] clean up code use proper types, move definitions to header file.
- [ ] Implementing fake copyClientEntitlement
- [ ] Implementing CompareCoverage(memcmp, strcmp,...)
- [ ] instrumenting kernel itself.
- [ ] Revisit BBs( What other BBs can we hook in)\
- [ ] decide on Hand writing the patch to use less REGs and remove them from push/pop to safe some cpu cycles! no PAC.
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

## Steps to Test Pishi in Parallels Desktop
1. **Build Kernel Extension (kext)**
   - Build the kext required for testing purposes.

2. **Create Extensions Folder**
   - Create a folder named `Extensions` and copy the generated kext into it.

3. **Set Permissions**
   - Run the following commands in Terminal to set appropriate permissions:
     ```bash
     sudo chown -R root:wheel Extensions/
     sudo chmod -R 755 Extensions/
     ```

4. **Inspect and Prepare kexts**
   - Run the command to inspect and prepare the kexts for loading:
     ```bash
     kmutil inspect -V release --no-header | grep -v "SEPHiber" | awk '{print " -b "$1; }' > kexts.txt
     ```

5. **Add Custom kext**
   - Append the custom kext to the `kexts.txt` file:
     ```bash
     echo "-b Kcov.macOS.Pishi" >> kexts.txt
     ```

6. **Create Bootable Kernel Cache**
   - Execute the following command to create the bootable kernel cache:
     ```bash
     kmutil create -z -V release -n boot -B vmboot.kc -k /System/Library/kernels/kernel.release.vmapple -r Extensions/ -x $(cat kexts.txt)
     ```

7. **Load and Analyze with Ghidra**
   - Load the generated `vmboot.kc` file in Ghidra.
   - Select `Function Start Search` in Ghidra to optimize analysis time.

8. **Run Instrumentation Script**
   - Load and execute the `instrument.py` script in Ghidra.

9. **Save Original File**
   - Export the original file in Ghidra by selecting `File -> Export Program` (or using the `o` shortcut). Choose `Original file` as the format and save it.

10. **Prepare for System Reboot**
    - Reboot the system and enter Recovery Mode.
    - Disable SIP (System Integrity Protection) by running:
      ```bash
      csrutil disable
      ```
    - Enable boot-args modification by running:
      ```bash
      bputil -a
      ```

11. **Configure Boot with Custom Kernel Cache**
    - After rebooting, execute the following command:
      ```bash
      kmutil configure-boot -v /Volumes/Macintosh\ HD/ -c $PATH_TO_YOUR_saved_kc_file_in_ghidra
      ```

12. **Final System Reboot**
    - Reboot the system and wait for it to boot with the configured kernel settings.

