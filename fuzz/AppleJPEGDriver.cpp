/*
build:
 ../bin/clang -fsanitize=fuzzer /Users/meysam/projects/macho/cov/hello.mm -o meysam -isysroot $(xcrun --show-sdk-path)
 */

#include <stdio.h>
#include <assert.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurface.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#define DEVICE_NAME "/dev/pishi"
#define PISHI_IOC_MAP _IOWR('K', 8, struct pishi_buf_desc)
#define PISHI_IOC_START _IOW('K', 10, uintptr_t)
#define PISHI_IOC_STOP _IOW('K', 20, uint64_t)
#define PISHI_IOC_UNMAP _IOW('K', 30, uint64_t)
#define PISHI_IOC_TEST _IOW('K', 40, uintptr_t)
#define PISHI_IOC_FUZZ _IOW('K', 50, char *)

struct pishi_buf_desc
{
  uintptr_t ptr; /* ptr to shared buffer [out] */
  size_t sz;     /* size of shared buffer [out] */
};

struct kcov
{
  unsigned long kcov_pos;
  uintptr_t kcov_area[0];
};

int covfd;
struct pishi_buf_desc mc = {0};
char _pishi_libfuzzer_coverage[32 << 10];

void kcov_start()
{
  int a;
  if (ioctl(covfd, PISHI_IOC_START, &a) == -1)
  {
    perror("Failed to perform ioctl PISHI_IOC_START");
    close(covfd);
    exit(0);
  }
}

void kcov_collect()
{
  struct kcov *coverage = (struct kcov *)mc.ptr;

  for (int i = 0; i < coverage->kcov_pos; i++)
  {
    uint64_t pc = coverage->kcov_area[i];
    _pishi_libfuzzer_coverage[pc % sizeof(_pishi_libfuzzer_coverage)]++;
  }
}

void kcov_stop()
{
  uint64_t data_to_send = 12345; // Example data to send
  if (ioctl(covfd, PISHI_IOC_STOP, &data_to_send) == -1)
  {
    perror("Failed to perform ioctl PISHI_IOC_STOP");
    exit(0);
    close(covfd);
  }

  kcov_collect();
}

io_service_t service;
io_connect_t connect;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  int value;
  covfd = open(DEVICE_NAME, O_RDWR);
  if (covfd == -1)
  {
    perror("Failed to open device");
    exit(0);
    return EXIT_FAILURE;
  }

  // Perform the ioctl operation
  if (ioctl(covfd, PISHI_IOC_MAP, &mc) == -1)
  {
    perror("Failed to perform ioctl PISHI_IOC_MAP");
    exit(0);
    close(covfd);
    return EXIT_FAILURE;
  }
// kIOMainPortDefault old:kIOMasterPortDefault
  io_service_t service = IOServiceGetMatchingService(
      kIOMainPortDefault,
      IOServiceMatching("AppleJPEGDriver"));
  if (service == IO_OBJECT_NULL)
  {
    printf("%s: %x", "IOServiceGetMatchingService\n", service);
    exit(0);
  }

  kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
  IOObjectRelease(service);
  if (kr != KERN_SUCCESS)
  {
    printf("%s: %x", "IOServiceOpen\n", kr);
    exit(0);
  }

  return EXIT_SUCCESS;
}

// TODO:
//
//  next step instrument file system fuzzing.  ExFAT and APFS
//  implement fuzzer
//
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  kcov_start();

  uint32_t input_scalars_count = 0;
  uint64_t *input_scalars = NULL;
  size_t input_structure_size = 0x58;
  uint8_t input_structure[input_structure_size];
  uint32_t output_scalars_count = 0;
  uint64_t *output_scalars = NULL;
  uint32_t output_scalars_count_result = output_scalars_count;

  size_t output_structure_size = 0x1000;
  uint8_t output_structure[output_structure_size];
  size_t output_structure_size_result = output_structure_size;

  IOConnectCallMethod(
      connect, 1,
      NULL, 0,
      data, size,
      NULL, &output_scalars_count_result,
      output_structure, &output_structure_size_result);

  kcov_stop();
  return 0;
}
