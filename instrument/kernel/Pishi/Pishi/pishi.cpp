//
//  Pishi.cpp
//  Pishi
//
//  Created by Meysam Firouzi on 30.06.24.

#include "pishi.hpp"

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

IOMemoryMap* currnet_task_map = NULL;
IOBufferMemoryDescriptor* memoryDescriptor = NULL;
uint64_t instrumented_thread = UINT_MAX;

bool do_instrument = false;
bool do_log = true;
bool isDeviceOpen = false;
kcov* coverage_area= NULL;

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

void print_message(const char *format, ...)
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

uint64_t* map_memoryinto_current_task()
{
    memoryDescriptor = createSharedMemory( sizeof(kcov) + (0x20000 * (sizeof(uintptr_t)) ));
    if ( !memoryDescriptor ) {

        print_message("[PISHI] Failed to create memory descriptor\n");
        return NULL;
    }
    
    currnet_task_map = memoryDescriptor->createMappingInTask(current_task(), 0, kIOMapAnywhere);
    
    if ( !currnet_task_map ) {

        print_message("[PISHI] Failed to map memory descriptor\n");
        memoryDescriptor->release();
        memoryDescriptor = NULL;
        return NULL;
    }
    
    coverage_area = (kcov*) memoryDescriptor->getBytesNoCopy();;
    coverage_area->kcov_pos = 0;
    
    return (uint64_t*) currnet_task_map->getVirtualAddress();
}

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
    coverage_area = NULL;
    
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
            
            print_message("[PISHI] PISHI_IOCTL_MAP instrumented_thread %llu do_instrument %d\n", instrumented_thread, do_instrument);
            if( coverage_area ) {

                print_message("[PISHI] PISHI_IOCTL_MAP IOCTLTL instrument_buffer is already mapped\n");
                break;
            }
            
            uint64_t* maped_address =  map_memoryinto_current_task();
            if ( !maped_address ) {

                print_message("[PISHI] PISHI_IOCTL_MAP IOCTL maped_address is NULL\n");
                break;
            }
            
            pishi_buf_desc *p = (pishi_buf_desc*)_data;
            p->ptr = (user_addr_t) maped_address;
            p->sz = (user_size_t) sizeof(kcov) + (0x20000 * sizeof(uintptr_t));
            
            do_instrument = false;
            instrumented_thread = UINT_MAX;

            break;
        }
            
        case PISHI_IOCTL_START: {
            
            print_message("[PISHI] PISHI_IOCTL_START ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            
            if ( do_instrument ) {

                print_message("[PISHI] PISHI_IOCTL_START do_instrument is already on\n");
                break;
            }
            
            if (!coverage_area) {

                print_message("[PISHI] PISHI_IOCTL_START coverage_area is NULL\n");
                break;
            }
            
            if( coverage_area )
                coverage_area->kcov_pos = 0;

            instrumented_thread = thread_tid(current_thread());
            do_instrument = true;

            break;
        }
        case PISHI_IOCTL_UNMAP: {

            print_message("[PISHI] PISI_IOCTL_UNMAP ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            do_instrument = false;
            instrumented_thread = UINT_MAX;
            coverage_area = NULL;

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
            print_message("[PISHI] PISI_IOCTL_STOP ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            break;
        }
        case PISHI_IOCTL_TEST: {

            print_message("[PISHI] PISI_IOCTL_TEST ThreadID %llu do_instrument %d\n", instrumented_thread, do_instrument);
            sanitizer_cov_trace_pc(0x41414141);
            break;
        }
        case PISHI_IOCTL_FUZZ: {
            fuzz_me((uintptr_t*)_data);
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

void push_regs()
{
    __asm__ __volatile__  (
            "sub sp, sp, #0x100\n"
            "str xzr, [sp, #0xf8]\n"
            "str x29, [sp, #0xe8]\n"
            "str x28, [sp, #0xe0]\n"
            "str x27, [sp, #0xd8]\n"
            "str x26, [sp, #0xd0]\n"
            "str x25, [sp, #0xc8]\n"
            "str x24, [sp, #0xc0]\n"
            "str x23, [sp, #0xb8]\n"
            "str x22, [sp, #0xb0]\n"
            "str x21, [sp, #0xa8]\n"
            "str x20, [sp, #0xa0]\n"
            "str x19, [sp, #0x98]\n"
            "str x18, [sp, #0x90]\n"
            "str x17, [sp, #0x88]\n"
            "str x16, [sp, #0x80]\n"
            "str x15, [sp, #0x78]\n"
            "str x14, [sp, #0x70]\n"
            "str x13, [sp, #0x68]\n"
            "str x12, [sp, #0x60]\n"
            "str x11, [sp, #0x58]\n"
            "str x10, [sp, #0x50]\n"
            "str x9, [sp, #0x48]\n"
            "str x8, [sp, #0x40]\n"
            "str x7, [sp, #0x38]\n"
            "str x6, [sp, #0x30]\n"
            "str x5, [sp, #0x28]\n"
            "str x4, [sp, #0x20]\n"
            "str x3, [sp, #0x18]\n"
            "str x2, [sp, #0x10]\n"
            "str x1, [sp, #0x8]\n"
            "str x0, [sp]\n"
            "sub sp, sp, #0x50\n"
            "ret"
        );
}

void pop_regs() {
    __asm__ __volatile__ (
        "add sp, sp, #0x50\n"
        "ldr xzr, [sp, #0xf8]\n"
        "ldr x29, [sp, #0xe8]\n"
        "ldr x28, [sp, #0xe0]\n"
        "ldr x27, [sp, #0xd8]\n"
        "ldr x26, [sp, #0xd0]\n"
        "ldr x25, [sp, #0xc8]\n"
        "ldr x24, [sp, #0xc0]\n"
        "ldr x23, [sp, #0xb8]\n"
        "ldr x22, [sp, #0xb0]\n"
        "ldr x21, [sp, #0xa8]\n"
        "ldr x20, [sp, #0xa0]\n"
        "ldr x19, [sp, #0x98]\n"
        "ldr x18, [sp, #0x90]\n"
        "ldr x17, [sp, #0x88]\n"
        "ldr x16, [sp, #0x80]\n"
        "ldr x15, [sp, #0x78]\n"
        "ldr x14, [sp, #0x70]\n"
        "ldr x13, [sp, #0x68]\n"
        "ldr x12, [sp, #0x60]\n"
        "ldr x11, [sp, #0x58]\n"
        "ldr x10, [sp, #0x50]\n"
        "ldr x9, [sp, #0x48]\n"
        "ldr x8, [sp, #0x40]\n"
        "ldr x7, [sp, #0x38]\n"
        "ldr x6, [sp, #0x30]\n"
        "ldr x5, [sp, #0x28]\n"
        "ldr x4, [sp, #0x20]\n"
        "ldr x3, [sp, #0x18]\n"
        "ldr x2, [sp, #0x10]\n"
        "ldr x1, [sp, #0x8]\n"
        "ldr x0, [sp]\n"
        "add sp, sp, #0x100\n"
        "ret\n"
    );
}

void sanitizer_cov_trace_pc(uintptr_t address)
{
    if (__improbable(do_instrument)) {
        
        if (__improbable(coverage_area == NULL))
            return;
        
        if(__improbable(instrumented_thread == thread_tid(current_thread()))) {

            /* The first 64-bit word is the number of subsequent PCs. */
            if (__probable(coverage_area->kcov_pos < 0x20000)) {

                unsigned long pos = coverage_area->kcov_pos;
                coverage_area->kcov_area[pos] = address;
                coverage_area->kcov_pos +=1;
            }
        }
    }
}

void sanitizer_cov_trace_lr()
{
    if (__improbable(do_instrument)) {
        
        if (__improbable(coverage_area == NULL))
            return;
        
        if(__improbable(instrumented_thread == thread_tid(current_thread()))) {

            /* The first 64-bit word is the number of subsequent PCs. */
            if (__probable(coverage_area->kcov_pos < 0x20000)) {

                unsigned long pos = coverage_area->kcov_pos;
                /*
                    each block represent unique BB.
                    TODO: 1- Get real BB address. 2- unslide.
                */
                coverage_area->kcov_area[pos] = (uintptr_t)__builtin_return_address(0);
                coverage_area->kcov_pos +=1;
            }
        }
    }
}

#ifdef USE_UNSLIDE
void instrument_thunks()
{
    asm volatile (
                  ".rept " xstr(REPEAT_COUNT_THUNK) "\n"  // Repeat the following block many times
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
#else
void instrument_thunks()
{
    asm volatile (
                  ".rept " xstr(REPEAT_COUNT_THUNK) "\n"  // Repeat the following block many times
                  "    STR x30, [sp, #-16]!\n"      // save LR. we can't restore it in pop_regs. as we have jumped here.
                  "    bl _push_regs\n"
                  "    bl _sanitizer_cov_trace_lr\n"
                  "    bl _pop_regs\n"
                  "    LDR x30, [sp], #16\n"        // restore LR
                  "    nop\n"
                  "    nop\n"
                  ".endr\n"                         // End of repetition
                  );
}
#endif

void fuzz_me(uintptr_t* p)
{
    int error = 0;
    size_t len;
    char k_buffer[0x100] = {0};
    
    error = copyinstr((user_addr_t)*p, k_buffer, sizeof(k_buffer), &len);
    if (error) {
        print_message("[PISHI] can't copyinstr\n");
        return;
    }
    
    if (strlen(k_buffer) > 9)
        if(k_buffer[0] =='M')
            if(k_buffer[1] =='E')
                if(k_buffer[2] =='Y')
                    if(k_buffer[3] =='S')
                        if(k_buffer[4] =='A')
                            if(k_buffer[5] =='M')
                                if(k_buffer[6] =='6')
                                    if(k_buffer[7] =='7')
                                        if(k_buffer[8] =='8')
                                            if(k_buffer[9] =='9') {
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

        print_message("[PISHI] failed to allocate major device node\n");
        return ;
    }
    dev_t dev = makedev(dev_major, 0);
    void *node = devfs_make_node_clone(dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666,
                                       ksancov_dev_clone, PISHI_DEVNODE);
    if (!node) {

        print_message("[PISHI] Failed to create device node\n");
    }
    
    print_message("[PISHI] instrumented_thread %llu, do_instrument %d\n" ,instrumented_thread, do_instrument);
}

void create_dev_thread(thread_continue_t calllback)
{
    thread_t thread;
    kernel_thread_start(calllback, NULL, &thread);
    thread_deallocate(thread);
}

kern_return_t Pishi_start(kmod_info_t * ki, void *d)
{
    // probably at this stage we are too early to be able to create a dev_node, it fails, so I create it in another thread after 1 second.
    create_dev_thread(thread_create_dev_callback);
    return KERN_SUCCESS;
}

}
