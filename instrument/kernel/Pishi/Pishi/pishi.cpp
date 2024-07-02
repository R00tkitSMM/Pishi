//
//  Pishi.cpp
//  Pishi
//
//  Created by Meysam Firouzi on 30.06.24.

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

// fake entitlement checkers
class IOFuzzClient {
public:
    OSObject * copyClientEntitlement(task_t task, const char* entitlement);
    OSObject * AMFIcopyClientEntitlement(task_t task, const char* entitlement);
};

OSObject * IOFuzzClient::copyClientEntitlement( task_t task,const char* entitlement )
{
    return kOSBooleanTrue;
}

OSObject * IOFuzzClient::AMFIcopyClientEntitlement( task_t task,const char* entitlement )
{
    return kOSBooleanTrue;
}

extern "C" {

#define PISHI_IOCTL_MAP          _IOWR('K', 8, struct pishi_buf_desc)
#define PISHI_IOCTL_START        _IOW('K', 10, uintptr_t)
#define PISHI_IOCTL_STOP         _IOW('K', 20, uint64_t)
#define PISHI_IOCTL_UNMAP        _IOW('K', 30, uint64_t)
#define PISHI_IOCTL_TEST         _IOW('K', 40, uintptr_t)
#define PISHI_IOCTL_FUZZ         _IOW('K', 50, char*)

#define PISHI_DEVNODE "pishi"
#define PISHNI_PATH "/dev/" PISHI_DEVNODE

kern_return_t helper_start(kmod_info_t* ki, void *d);
kern_return_t helper_stop(kmod_info_t* ki, void *d);
static int pishi_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p);
static int pishi_open(dev_t dev, int flags, int devtype, proc_t p);
static int pishi_close(dev_t dev, int flags, int devtype, proc_t p);
void sanitizer_cov_trace_pc(uint64_t address);
void fuzz(char*  buffer);

uintptr_t* instrument_buffer = NULL;
IOMemoryMap* currnet_task_map = NULL;
IOBufferMemoryDescriptor* memoryDescriptor = NULL;

bool do_instrument = false;
volatile bool do_log = false;

uint64_t instrumented_thread = UINT_MAX;

static int dev_major;

static const struct cdevsw
pishi_cdev = {
    .d_open =  pishi_open,
    .d_close = pishi_close,
    .d_ioctl = pishi_ioctl,
    
    .d_read = eno_rdwrt,
    .d_write = eno_rdwrt,
    .d_stop = eno_stop,
    .d_reset = eno_reset,
    .d_select = eno_select,
    .d_mmap = eno_mmap,
    .d_strategy = eno_strat,
    .d_type = 0
};

struct kcov {
    unsigned long kcov_pos;
    uintptr_t kcov_area[0];
};

struct pishi_buf_desc {
    uintptr_t ptr;  /* ptr to shared buffer [out] */
    size_t sz;      /* size of shared buffer [out] */
};

void my_printf(const char *format, ...)
{
    if( do_log ) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

IOBufferMemoryDescriptor * createSharedMemory(size_t size)
{
    IOBufferMemoryDescriptor* memoryDescriptor = NULL;
    memoryDescriptor = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn | kIOMemoryKernelUserShared, size, PAGE_SIZE);
    return memoryDescriptor;
}

uintptr_t* map_memoryinto_current_task()
{
    memoryDescriptor = createSharedMemory( sizeof(kcov) + (0x20000 * (sizeof(uintptr_t)) ));
    if ( !memoryDescriptor ) {

        my_printf("[meysam] Failed to create memory descriptor\n");
        return NULL;
    }
    
    currnet_task_map = memoryDescriptor->createMappingInTask(current_task(), 0, kIOMapAnywhere);
    
    if ( !currnet_task_map ) {

        my_printf("[meysam] Failed to map memory descriptor\n");
        memoryDescriptor->release();
        memoryDescriptor = NULL;
        return NULL;
    }
    
    instrument_buffer = (uintptr_t*) memoryDescriptor->getBytesNoCopy();
    return (uintptr_t*) currnet_task_map->getVirtualAddress();
}

static bool isDeviceOpen = false;

static int
pishi_open(dev_t dev, int flags, int devtype, proc_t p)
{
    if ( isDeviceOpen ) {

        return -EBUSY;
    }
    
    isDeviceOpen = true;
    return 0;
}

static int
pishi_close(dev_t dev, int flags, int devtype, proc_t p)
{
    do_instrument = false;
    instrumented_thread = UINT_MAX;
    instrument_buffer = NULL;
    
    if ( memoryDescriptor ) {

        memoryDescriptor->release();
        memoryDescriptor = NULL;
    }
    
    if( currnet_task_map ) {

        currnet_task_map->release();
        currnet_task_map = NULL;
    }
    
    isDeviceOpen = false;
    return 0;
}

static int
pishi_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p)
{
    switch (cmd) {

        case PISHI_IOCTL_MAP: {
            
            my_printf("[meysam] PISHI_IOCTL_MAP instrumented_thread %llu do_instrument %d" ,instrumented_thread, do_instrument);
            if( instrument_buffer ) {

                my_printf("[meysam] PISHI_IOCTL_MAP IOCTLTL instrument_buffer is already mapped\n");
                break;
            }
            
            uintptr_t* maped_address =  map_memoryinto_current_task();
            if ( !maped_address ) {

                my_printf("[meysam] PISHI_IOCTL_MAP IOCTL maped_address is NULL\n");
                break;
            }
            
            pishi_buf_desc *p = (pishi_buf_desc*)_data;
            p->ptr = (uintptr_t)maped_address;
            p->sz = sizeof(kcov) + (0x20000 * sizeof(uintptr_t));
            
            do_instrument = false;
            instrumented_thread = UINT_MAX;
            kcov* area = (kcov*) instrument_buffer;
            area->kcov_pos = 0;
            
            break;
        }
            
        case PISHI_IOCTL_START: {
            
            my_printf("[meysam] PISHI_IOCTL_START ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            if (!instrument_buffer) {

                my_printf("[meysam] PISHI_IOCTL_START instrument_buffer is NULL\n");
                break;
            }
            if ( do_instrument ) {

                my_printf("[meysam] PISHI_IOCTL_START do_instrument is already on\n");
                break;
            }
            
            kcov* area = (kcov*) instrument_buffer;
            if( area )
                area->kcov_pos = 0;

            instrumented_thread = thread_tid(current_thread());
            do_instrument = true;

            break;
        }
        case PISHI_IOCTL_UNMAP: {

            my_printf("[meysam] PISI_IOCTL_UNMAP ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            do_instrument = false;
            instrumented_thread = UINT_MAX;
            instrument_buffer = NULL;

            if ( memoryDescriptor ) {

                memoryDescriptor->release();
                memoryDescriptor = NULL;
            }
            
            if( currnet_task_map ) {

                currnet_task_map->release();
                currnet_task_map = NULL;
            }

            break;
        }
        case PISHI_IOCTL_STOP: {

            do_instrument = false;
            instrumented_thread = UINT_MAX;
            my_printf("[meysam] PISI_IOCTL_STOP ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            break;
        }
        case PISHI_IOCTL_TEST: {

            my_printf("[meysam] PISI_IOCTL_TEST ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            sanitizer_cov_trace_pc(0x4141414141);
            break;
        }
        case PISHI_IOCTL_FUZZ: {

            fuzz((char*)_data);
            break;
        }
    }
    return 0;
}

static int
ksancov_dev_clone(dev_t dev, int action)
{
    return 0;
}

void sanitizer_cov_trace_pc(uint64_t address)
{
    if (__improbable(do_instrument)) {

        my_printf("[meysam] sanitizer_cov_trace_pc instrumented_thread %llu do_instrument %d\n", instrumented_thread, do_instrument);
        
        if (__improbable(instrument_buffer == NULL))
            return;
        
        if(__improbable(instrumented_thread == thread_tid(current_thread()))) {

            kcov* area = (kcov*) instrument_buffer;
            /* The first 64-bit word is the number of subsequent PCs. */
            if (__probable(area->kcov_pos < 0x20000)) {

                unsigned long pos = area->kcov_pos;
                area->kcov_area[pos] = address;
                area->kcov_pos +=1;
            }
        }
    }
}

void push_regs()
{
    asm volatile (".rept 200\n"  // Repeat the following 174762 times to get approximately 5MB
                  "nop\n"
                  ".endr\n"
                  );
};

void pop_regs()
{
    asm volatile (".rept 200\n"  // Repeat the following 174762 times to get approximately 5MB
                  "nop\n"
                  ".endr\n"
                  );
};

void instrument_thunks()
{
    asm volatile (
                  ".rept 100000\n"                  // Repeat the following block many times
                  "    STR x30, [sp, #-16]!\n"      // save LR. we can't restore it in pop_regs. as we have jumped here.
                  "    bl _push_regs\n"
                  "    mov x0, #0x4141\n"           // fix the correct numner when instrumenting as arg0.
                  "    mov x0, #0x4141\n"
                  "    mov x0, #0x4141\n"
                  "    mov x0, #0x4141\n"
                  "    bl _sanitizer_cov_trace_pc\n"
                  "    bl _pop_regs\n"
                  "    LDR x30, [sp], #16\n"        // restore LR
                  "    nop\n"
                  "    nop\n"
                  ".endr\n"                         // End of repetition
                  );
}

void fuzz(char* buffer) {
    
    if (strlen(buffer) > 5)
        if(buffer[0] =='M')
            if(buffer[1] =='E')
                if(buffer[2] =='Y')
                    if(buffer[3] =='S') {
                        printf("boom!\n");
                        int* p = (int*)0x41414141;
                        *p = 0x42424242;
                    }
}


kern_return_t Pishi_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}

void thread_create_dev_callback(void *, wait_result_t)
{
    IOSleep(1000);
    dev_major = cdevsw_add(-1, &pishi_cdev);
    if (dev_major < 0) {

        my_printf("meysam: failed to allocate major device node\n");
        return ;
    }
    dev_t dev = makedev(dev_major, 0);
    void *node = devfs_make_node_clone(dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666,
                                       ksancov_dev_clone, PISHI_DEVNODE);
    if (!node) {

        my_printf("meysam: failed to create device node\n");
    }
    
    my_printf("[meysam:thread_create_dev_callback] instrumented_thread %llu, do_instrument %d\n" ,instrumented_thread, do_instrument);
}

void create_dev_thread(thread_continue_t calllback)
{
    thread_t thread;
    kernel_thread_start(calllback, NULL, &thread);
    thread_deallocate(thread);
}

kern_return_t Pishi_start(kmod_info_t * ki, void *d)
{
    // at this stage we are too early to be able to create a dev_node so I create it in another thread after 1 second.
    create_dev_thread(thread_create_dev_callback);
    return KERN_SUCCESS;
}

}
