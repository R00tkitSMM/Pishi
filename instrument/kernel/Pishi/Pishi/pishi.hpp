//
//  pishi.hpp
//  Pishi
//
//  Created by Meysam Firouzi on 30.06.24.
//

#ifndef pishi_hpp
#define pishi_hpp

#include <stdio.h>
#include <mach/mach_types.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSBoolean.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <vm/pmap.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <miscfs/devfs/devfs.h>
#include <IOKit/IOService.h>
#include <sys/proc.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <libkern/OSAtomic.h>

extern "C" {

#define PISHI_IOCTL_MAP             _IOR('K', 8, struct pishi_buf_desc) // change to _IOR
#define PISHI_IOCTL_START           _IOW('K', 10, uint16_t)
#define PISHI_IOCTL_STOP            _IO('K', 20)
#define PISHI_IOCTL_UNMAP           _IO('K', 30)
#define PISHI_IOCTL_TEST            _IO('K', 40)
#define PISHI_IOCTL_FUZZ            _IOW('K', 50, char *)

/*
    If USE_UNSLIDE is defined, the instrument will call sanitizer_cov_trace_pc, allowing us to obtain the unslid and correct basic block (BB) address.
    Also have to set USE_UNSLIDE to True in instrument.py
    USE_UNSLIDE will produce bigger mach-o file.
*/
#define USE_UNSLIDE
#define REPEAT_COUNT_THUNK 120000
#define str(s) #s
#define xstr(s) str(s)
#define PISHI_DEVNODE "pishi"
#define PISHNI_PATH "/dev/" PISHI_DEVNODE

kern_return_t helper_start(kmod_info_t* ki, void *d);
kern_return_t helper_stop(kmod_info_t* ki, void *d);
static int pishi_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p);
static int pishi_open(dev_t dev, int flags, int devtype, proc_t p);
static int pishi_close(dev_t dev, int flags, int devtype, proc_t p);
void sanitizer_cov_trace_pc(uint16_t kext, uintptr_t address);
void sanitizer_cov_trace_lr(uint16_t kext);
void fuzz_me(uintptr_t* p);


struct kcov {
    uint64_t kcov_pos;
    uintptr_t kcov_area[0];
};

struct pishi_buf_desc {
    user_addr_t ptr;
    user_size_t sz;
};

}
#endif /* pishi_hpp */
