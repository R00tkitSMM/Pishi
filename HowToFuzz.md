
## Steps to test Pishi
1. Build Kernel Extension (kext)
2. Create Extensions directory
   - Create a folder named `Extensions` and copy the generated kext into it.
3. Copy a Kext(e.g IOSurface.kext) from KDK to `Externtions` folder and add
```bash
        <key>Kcov.macOS.Pishi</key>
        <string>1</string>
``` 
to `IOSurface.kext/Contents/Info.plist` file
4. Set permissions
   - Run the following commands in Terminal to set appropriate permissions for the directory Extensions:
     ```bash
     sudo chown -R root:wheel Extensions/
     sudo chmod -R 755 Extensions/
     ```
5. Inspect and prepare KEXTs
   - in target: Run the command to inspect and prepare the list of kext for loading in the text environment:
     ```bash
     kmutil inspect -V release --no-header | grep -v "SEPHiber" | awk '{print " -b "$1; }' > kexts.txt
     ```
6. Add custom KEXT
   - Append the custom kext to the `kexts.txt` file:
     ```bash
     echo "-b Kcov.macOS.Pishi" >> kexts.txt
     ```
7. Create a bootable kernel cache
   - Execute the following command to create the bootable kernel cache:
     ```bash
     kmutil create -z -V release -n boot -B boot.kc -k /System/Library/kernels/kernel.release.vmapple -r Extensions/ -x $(cat kexts.txt)
     ```

8. Load and analyze with Ghidra
   - Load the generated `boot.kc` file in Ghidra.
   - Select `Function Start Search` in Ghidra to optimize analysis time.

9. Run instrumentation script
   - Load and execute the `instrument_kext.py` script in Ghidra.

10. Save the instrumentated boot.kc
   - Export the original file in Ghidra by selecting `File -> Export Program` (or using the `o` shortcut). Choose `Original file` as the format and save it.

11. Prepare for system reboot
    - Reboot the system and enter Recovery Mode.
    - Disable SIP (System Integrity Protection) by running:
      ```bash
      csrutil disable
      ```
    - Enable boot-args modification by running: ( this is not necessary!) 
      ```bash
      bputil -a
      ```

12. Configure macine to boot with custom kernel cache
    - After rebooting, execute the following command:
      ```bash
      kmutil configure-boot -v /Volumes/Macintosh\ HD/ -c $PATH_TO_YOUR_saved_kc_file_in_ghidra
      ```

13. Final system reboot
    - Reboot the system and wait for it to boot with the configured kernel settings.

