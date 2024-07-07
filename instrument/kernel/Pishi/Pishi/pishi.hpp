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

#define PISHI_IOCTL_MAP          _IOWR('K', 8, struct pishi_buf_desc)
#define PISHI_IOCTL_START        _IOW('K', 10, uintptr_t)
#define PISHI_IOCTL_STOP         _IOW('K', 20, uint64_t)
#define PISHI_IOCTL_UNMAP        _IOW('K', 30, uint64_t)
#define PISHI_IOCTL_TEST         _IOW('K', 40, uintptr_t)
#define PISHI_IOCTL_FUZZ         _IOW('K', 50, uint64_t)


#define str(s) #s
#define xstr(s) str(s)
#define REPEAT_COUNT_THUNK1 0
#define REPEAT_COUNT_THUNK2 60000

#define PISHI_DEVNODE "pishi"
#define PISHNI_PATH "/dev/" PISHI_DEVNODE

kern_return_t helper_start(kmod_info_t* ki, void *d);
kern_return_t helper_stop(kmod_info_t* ki, void *d);
static int pishi_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p);
static int pishi_open(dev_t dev, int flags, int devtype, proc_t p);
static int pishi_close(dev_t dev, int flags, int devtype, proc_t p);
void sanitizer_cov_trace_pc(uintptr_t address);
void sanitizer_cov_trace_lr();
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
