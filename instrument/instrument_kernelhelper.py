#@author Meysam
#@category macOS.kernel

import os
import json
import jarray
import subprocess

INSTRUCTION_SIZE = 4
FUNC_ADDRESS = 0
FUNC_SIZE = 1
FUNC_OPCODES = 2
FUNC_NAME = 3

def assemble_opcode(assembler, address, opcode):
     assembler.assemble(address, opcode)
     return address.add(INSTRUCTION_SIZE) # size of each inst

def check_nonrelative(inst):

    Instruction = [
        'and',  'ldadd',   'stur',  'mov',
        'add',   'str',    'ldp',   'bfxil'
        'stp',   'mul',    'lsl',   'sub',
        'lsr',   'cmp',    'tst',   'ldur',
        'orn',   'bic',    'cmn',   'eon',
        'neg',   'adc',    'mvn',   'ana',
        'eor',   'sbc',    'orr',   'ldset',
        'ubfx',  'msub',   'udiv',  'cmhs',
        'xtn',   'fmov',   'sxtw',  'ccmp',
        'asr',   'strb',   'sbfx',  'bfi',
        'strh',  'xtn',    'uxtn',  'sxtw',
        'sxtb',  'sxth',   'uxth',  'uxtb'
        ]

    for i in Instruction:
        if inst.startswith(i):
            return True
    return False

def get_kext(kext):
    program = currentProgram
    memory = program.getMemory()

    # Check if the file is Mach-O
    if not "Mach-O" in program.getExecutableFormat():
        print("This script only works with Mach-O files.")
        return [None, None]

    blocks = memory.getBlocks()
    for block in blocks:
        if block.sourceName == kext:
            if "__text" in block.getName():
                print(" Start: {}".format(block.getStart()))
                print(" End: {}".format(block.getEnd()))
                print(" Size: {}".format(block.getSize()))
                print(" sourceName: {}".format(block.sourceName))
                return [str(block.getStart()), str(block.getEnd())]

    return [None, None]


# TODO: block list this functions
# https://github.com/apple-oss-distributions/xnu/blob/main/san/coverage/kcov-blacklist-arm64
# https://github.com/apple-oss-distributions/xnu/blob/main/san/coverage/kcov-blacklist

ingnore_list = [
    "machine_routines_common.c",
    "ml_at_interrupt_context",
    "ml_stack_remaining",
    "ml_stack_base",
    "ml_stack_size",
    "kernel_preempt_check",
    "pmap_interrupts_disable",
    "pmap_get_cpu_data",
    "ml_get_ppl_cpu_data",
    "pmap_interrupts_restore",
    "ksancov_",
    "kcov_",
    "dtrace_",
    "kcov.c",
    "kcov_ksancov.c",
    "kcov_stksz.c",
    "/san/memory/",
    "debug.c",
    "disable_preemption",
    "enable_preemption",
    "current_thread",
    "ml_at_interrupt_context",
    "get_interrupt_level",
    "get_active_thread",
    "cpu_datap",
    "cpu_number",
    "get_cpu_number",
    "pmap_in_ppl",
    "get_preemption_level",
    "vm_memtag_add_ptr_tag",
    "ml_static_unslide",
    "vm_is_addr_slid"
]

def ingnore_me(path):

    for case in ingnore_list:
        if case in path:
            return True

    return False


def get_path(patterns):

    command = [
        "dwarfdump",
        "/Users/meysam/project/Pishi/kernels/Kernels/kernel.release.vmapple.dSYM/Contents/Resources/DWARF/kernel.release.vmapple"
    ]

    result = subprocess.check_output(command)
    decoded_result = result.decode('ascii', errors='ignore')
    lines = decoded_result.splitlines()
    map_name_line = []
    for index, line in enumerate(lines):
        name = None
        line_name = None
        if "DW_TAG_subprogram" in line:
            for i in range(1, 10):
                if index + i < len(lines) and "DW_AT_name" in lines[index + i]:
                    name = lines[index + i].replace("DW_AT_name", "").strip().replace("(", "").replace(")", "").replace("\"", "")
                if index + i < len(lines) and "DW_AT_decl_file" in lines[index + i]:
                    line_name = lines[index + i].replace("DW_AT_decl_file", "").strip().replace("(", "").replace(")", "").replace("\"", "")
        if name and line_name:
            if ingnore_me(line_name):
                continue
            for pattern in patterns:
                if pattern in line_name:
                    map_name_line.append(str(name))

    return map_name_line

osfmk = [
    "/osfmk/ipc",
    "/osfmk/vm",
    "/osfmk/voucher",
    "osfmk/kern/hv_io_notifier.c",
    "osfmk/kern/hv_support_kext.c",
    "osfmk/kern/iotrace.c",
    "osfmk/kern/kalloc.c",
    "osfmk/kern/kern_apfs_reflock.c",
    "osfmk/kern/kern_cdata.c",
    "osfmk/kern/kern_monotonic.c",
    "osfmk/kern/kern_stackshot.c",
    "osfmk/kern/kext_alloc.c",
    "osfmk/kern/kmod.c",
    "osfmk/kern/mk_timer.c",
    "osfmk/kern/mpsc_queue.c",
    "osfmk/kern/page_decrypt.c",
    "osfmk/kern/printf.c",
    "osfmk/kern/priority.c",
    "osfmk/kern/processor.c",
    "osfmk/kern/recount.c",
    "osfmk/kern/remote_time.c",
    "osfmk/kern/restartable.c",
    "osfmk/kern/kpc_common.c",
    "osfmk/kern/kpc_thread.c",
    "osfmk/kern/ledger.c",
    "osfmk/kern/lock_group.c",
    "osfmk/kern/lock_mtx.c",
    "osfmk/kern/lock_ptr.c",
    "osfmk/kern/lock_rw.c",
    "osfmk/kern/lock_ticket.c",
    "osfmk/kern/locks.c",
    "osfmk/kern/mach_node.c",
    "osfmk/kern/machine.c",
    "osfmk/kern/mk_sp.c",
    "osfmk/kern/affinity.c",
    "osfmk/kern/arcade.c",
    "osfmk/kern/ast.c",
    "osfmk/kern/audit_sessionport.c",
    "osfmk/kern/bsd_kern.c",
    "osfmk/kern/btlog.c",
    "osfmk/kern/build_config.c",
    "osfmk/kern/clock_oldops.c",
    "osfmk/kern/clock.c",
    "osfmk/kern/coalition.c",
    "osfmk/kern/compact_id.c",
    "osfmk/kern/copyout_shim.c",
    "osfmk/kern/core_analytics.c",
    "osfmk/kern/counter_common.c",
    "osfmk/kern/cpc.c",
    "osfmk/kern/debug.c",
    "osfmk/kern/ecc_logging.c",
    "osfmk/kern/energy_perf.c",
    "osfmk/kern/epoch_sync.c",
    "osfmk/kern/exception.c",
    "osfmk/kern/ext_paniclog.c",
    "osfmk/kern/extmod_statistics.c",
    "osfmk/kern/hibernate.c",
    "osfmk/kern/host_notify.c",
    "osfmk/kern/host.c",
    "osfmk/kern/sched_amp_common.c",
    "osfmk/kern/sched_amp.c",
    "osfmk/kern/sched_average.c",
    "osfmk/kern/sched_clutch.c",
    "osfmk/kern/sched_dualq.c",
    "osfmk/kern/sched_grrr.c",
    "osfmk/kern/sched_multiq.c",
    "osfmk/kern/sched_prim.c",
    "osfmk/kern/sched_proto.c",
    "osfmk/kern/sched_traditional.c",
    "osfmk/kern/socd_client.c",
    "osfmk/kern/ipc_clock.c",
    "osfmk/kern/ipc_host.c",
    "osfmk/kern/ipc_kobject.c",
    "osfmk/kern/ipc_mig.c",
    "osfmk/kern/ipc_misc.c",
    "osfmk/kern/ipc_tt.c",
    "osfmk/kern/spl.c",
    "osfmk/kern/stack.c",
    "osfmk/kern/startup.c",
    "osfmk/kern/sync_sema.c",
    "osfmk/kern/syscall_subr.c",
    "osfmk/kern/syscall_sw.c",
    "osfmk/kern/sysdiagnose.c",
    "osfmk/kern/task_ident.c",
    "osfmk/kern/task_policy.c",
    "osfmk/kern/task_ref.c",
    "osfmk/kern/task.c",
    "osfmk/kern/telemetry.c",
    "osfmk/kern/test_lock.c",
    "osfmk/kern/timer_call.c",
    "osfmk/kern/timer.c",
    "osfmk/kern/turnstile.c",
    "osfmk/kern/ux_handler.c",
    "osfmk/kern/waitq.c",
    "osfmk/kern/work_interval.c",
    "osfmk/kern/workload_config.c"
    "osfmk/kern/test_mpsc_queue.c",
    "osfmk/kern/testpoints.c",  

    # "osfmk/kern/thread_act.c",
    # "osfmk/kern/thread.c",
    # "osfmk/kern/thread_call.c",
    # "osfmk/kern/thread_group.c",
    # "osfmk/kern/thread_policy.c",
   
    ]

bsd_net = ["bsd/net", "bsd/netinet", "bsd/netinet6", "bsd/netkey"]


def main():

    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()
    instrument_functions = []
    script_dir = os.path.dirname(os.path.abspath(__file__))


    map_name_line = map_name_line = get_path(osfmk) # get pattern from config

    kernel_text_start, kernel_text_end = get_kext("kernel.release.vmapple")

    kc_functions = function_manager.getFunctions(True)
    comapre = []
    instrument_functions.append([str(kernel_text_start), "", "", "kernel.release.vmapple"])
    for function in kc_functions:
            function_address = function.getEntryPoint()
            functionBody = function.getBody()
            functionSize = functionBody.getNumAddresses()

            instresting_path = False
            f_name = str(function.name)
            for i in map_name_line: # WTH the "in" is not working
                if i == f_name:
                    instresting_path = True
                    break

            if instresting_path is False:
                continue

            if (functionSize < INSTRUCTION_SIZE * 3):
                continue #ignore 2 instrctuon size function one is bti/pacibsp second is b or return.

            opcodes = []
            instresting = False
            for instruction in listing.getInstructions(functionBody, True):
                if "bti" in str(instruction) or "pacibsp" in str(instruction):
                    instresting = True
                else:
                    break

            if instresting is False:
                continue

            opcodes_index = 0
            for instruction in listing.getInstructions(functionBody, True):
                opcodes_index = opcodes_index + 1
                if check_nonrelative(str(instruction)):
                    if len(opcodes) > 3:
                        break
                    memory = currentProgram.getMemory()
                    original_opcode = jarray.zeros(INSTRUCTION_SIZE,"b") # it took me one day to find out about jarray.
                    memory.getBytes(function_address.add(INSTRUCTION_SIZE * opcodes_index ), original_opcode)
                    opcodes.append([opcodes_index, original_opcode.tolist()])
            comapre.append(function.name)
            instrument_functions.append([str(function_address), str(functionSize), opcodes, function.name])

    #   We don't see many functions here because they have been inlined. As a result, DWARF recognizes them, but Ghidra does not.
    #   print(set(map_name_line)-set(comapre))

    print("instrument_functions len {}".format(len(instrument_functions)))
    with open("{}/tagged_functions.json".format(script_dir), 'w') as f:
        json.dump(instrument_functions, f)


if __name__ == "__main__":
    main()