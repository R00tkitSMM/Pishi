sudo chown -R root:wheel Extensions/;sudo chmod  -R  755 Extensions/ 
kmutil create  -z -V release -n boot -B ./out/macosboot.kc -k /System/Library/kernels/kernel.release.t8122 -r Extensions/  -x $(cat kext_list)  
