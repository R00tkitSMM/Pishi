sudo chown -R root:wheel Extensions/;sudo chmod  -R  755 Extensions/ 
kmutil create  -z -V release -n boot -B ./out/vmboot.kc -k /System/Library/kernels/kernel.release.vmapple -r Extensions/    -x $(cat kext_list_vm)
