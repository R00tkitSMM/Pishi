# Pishi
macOS kernel KCOV
TODO: 
- [ ]  patch non relative instrctions.( proper BB detection). DO WE NEED THIS?
- [X]  ignore other threads
- [X]  KCOV, send coverage to user mode via shared memory


stpes to test.

1. build kext 
2. run commands in vmbuild.sh
3. load kc file in ghidra
4. load instrument.py in ghidra 
5. add what you want to instrument in config.json. e.g apfs kext file code section 
6. run the script ( before that you have to rename 3 labels _push_regs, _pop_regs and _thunks)
7. run the script and after it finished save the the original file somewhere.
8. reboot the system and go to recovery mode.
9. run "kmutil configure-boot -v /Volumes/Macintosh\ HD/ -c $PATH_TO_YOUR_kc_file"
10. make sure the SIP is off.
11. following commands 
( I havce to check if this setp is necessary) 
bputil -a # to enable boot-args modification
reboot 
then sudo 
sudo nvram boot-args="amfi_get_out_of_my_way=1 amfi_allow_any_signature=1 --arm64e_preview_abi -show_pointers"
nvram boot-args # to confirm 



