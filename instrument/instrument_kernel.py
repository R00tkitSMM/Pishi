#@author Meysam
#@category macOS.kernel

import os
import jarray
import json

from ghidra.program.model.listing import Instruction
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.plugin.assembler import Assemblers;
from ghidra.program.model.symbol import SourceType

INSTRUCTION_SIZE = 4
FUNC_ADDRESS = 0
FUNC_SIZE = 1
FUNC_OPCODES = 2
FUNC_NAME = 3

# if USE_UNSLIDE is defined, the instrument will call sanitizer_cov_trace_pc, allowing us to obtain the unslid and correct basic block (BB) address. 
# also you have to define this in pishi.hpp file.
USE_UNSLIDE = True


def assemble_opcode(assembler, address, opcode):
     assembler.assemble(address, opcode)
     return address.add(INSTRUCTION_SIZE) # size of each inst 

def check_nonrelative(inst):

     # TODO: add more Instruction.
     # the BL, BLR and BR are non relative. but we don't want to instrument them.

     # https://developer.arm.com/documentation/ddi0596/2020-12/Base-Instructions?lang=en
     # https://eclecticlight.co/2021/06/21/code-in-arm-assembly-working-with-pointers/

     # Relative instrctions:
     # B and its sub instrctions are PC relative
     # ADR: Form PC-relative address.
     # ADRP: Form PC-relative address to 4KB page. ( but it definitely has one "add" after it.)
     # LDR (literal): Load Register (literal).
     # LDRSW (literal): Load Register Signed Word (literal).
     # PRFM (literal): Prefetch Memory (literal).
 
    Instruction = [
    'and',  'ldadd',   'stur',  'mov',
    'add',   'str',    'ldp',   'bfxil'
    'stp',   'mul',    'lsl',   'sub'
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
        if str(inst).startswith(i):
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

def create_label(address, label_name):
    symbol_table = currentProgram.getSymbolTable() # type: ignore
    symbol_table.createLabel(address, label_name, SourceType.USER_DEFINED)

# compare some instructions to make sure this is correct function.
def compare_instructions(taged_function, kc_address):
    if taged_function[FUNC_OPCODES] == kc_address[FUNC_OPCODES]:
        return True
    return False

def target_function():

    targets = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    with open("{}/tagged_functions.json".format(script_dir)) as f:
        tagged_functions = json.load(f)

    start_address, end_address = get_kext("com.apple.kernel")

    kc_kerne_start_address = toAddr(start_address)
    kc_kernel_end_address  = toAddr(end_address)
    print(kc_kerne_start_address)
    print(kc_kernel_end_address)
    
    function_manager = currentProgram.getFunctionManager()

    k_start_address = None 
    done = 0
    for taged_function in tagged_functions:
        done = done + 1

        if done == 1: # get base address of kernel.release.vmapple
            k_start_address = toAddr(taged_function[FUNC_ADDRESS])
            continue

        taged_function_address = toAddr(taged_function[FUNC_ADDRESS])
        k_off = taged_function_address.subtract(k_start_address)

        kc_function_address =  kc_kerne_start_address.add(k_off) # if function size if 4 then add next address as function
        kc_function_address_end = kc_function_address.add(int(taged_function[FUNC_SIZE]))
        pointer = kc_function_address

        # ghidra can't correctly find functions, and it splits them to multiple valid/invalid functions/nonfunctions.
        # so we try to find all fucntuon in our range
        
        create_label(kc_function_address, taged_function[FUNC_NAME])

        while pointer < kc_function_address_end:
            is_function = function_manager.getFunctionAt(pointer)
            if is_function:
                functionBody = is_function.getBody()
                targets.append(pointer)
                pointer = pointer.add(functionBody.getNumAddresses())
                print(pointer)
            else:
                pointer = pointer.add(INSTRUCTION_SIZE)

    print("len targets {} ".format(done))
    print("len targets {} ".format(len(targets)))
    return targets

def get_basic_blocks(targets):
    # Iterate over the functions and print those within the address range
    all_basic_blocks = []
    for address in targets:
        function = getFunctionAt(address)
        if function:
            bb_addresses = do_function_basic_blocks(function)
            all_basic_blocks.append(bb_addresses)
            
    return all_basic_blocks

def generate_assembly_instructions(x64_number):
    if not isinstance(x64_number, str) or len(x64_number) > 16:
        raise ValueError("Input must be a 64-bit hexadecimal number as a string, e.g., 'fffffffffffffffe'")
    
    # Pad the hexadecimal number to ensure it is 16 characters long
    hex_number = x64_number.zfill(16)
    
    # Extract 16-bit segments
    segments = [hex_number[i:i+4] for i in range(0, len(hex_number), 4)]
    
    # Generate assembly instructions

    instructions = []
    instructions.append("mov  x1,#0x{}".format(segments[3]))
    instructions.append("movk x1,#0x{},LSL #16".format(segments[2]))
    instructions.append("movk x1,#0x{},LSL #32".format(segments[1]))
    instructions.append("movk x1,#0x{},LSL #48".format(segments[0]))
    return instructions

def assemble_opcode(assembler, address, opcode):
     assembler.assemble(address, opcode)
     return address.add(INSTRUCTION_SIZE) # size of each inst 

# Function to create a label at a specified address
def create_label(address, label_name):
    symbol_table = currentProgram.getSymbolTable() # type: ignore
    symbol_table.createLabel(address, label_name, SourceType.USER_DEFINED)

def get_opcode_by_address(address):
    listing = currentProgram.getListing() # type: ignore
    instruction = listing.getInstructionAt(address)
    if instruction is not None:
        return instruction


def do_function_basic_blocks(function):
    basic_blocks = []
    bm = BasicBlockModel(currentProgram) # type: ignore
    monitor = ConsoleTaskMonitor()
    blocks = bm.getCodeBlocksContaining(function.getBody(), monitor)

    while blocks.hasNext():
        bb = blocks.next()
        basic_blocks.append(bb)

    return basic_blocks


def clear_address(address, length):
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(address)
    if code_unit:
        listing.clearCodeUnits(address, address.add(length - 1), False)

class Instruction():
    def instrument(self, stub_address, patch_address, original_inst, needs_fix, bb_index, kext_index):

        print(bb_index)

        jump_back_instruction = "b {}".format("meysam_return_number_" + str(bb_index)) # Change this to your desired instruction

        original_opcode = jarray.zeros(INSTRUCTION_SIZE,"b") # it took me one day to find out about jarray.
        print("patch_address {}\n".format(patch_address))
        memory = currentProgram.getMemory()
        memory.getBytes(patch_address, original_opcode)

        assembler = Assemblers.getAssembler(currentProgram) # type: ignore
        create_label(stub_address, "meysam_stub_number_" + str(bb_index))
        create_label(patch_address.add(INSTRUCTION_SIZE), "meysam_return_number_" + str(bb_index))

        # Patch the BB to jump to out stub_address# label 
        patched_instruction = "b {}".format("meysam_stub_number_" + str(bb_index)) # Change this to your desired instruction
        assemble_opcode(assembler, patch_address, patched_instruction)

        # "str x30, [sp, #-0x10]!"
        # "bl push_regs"
        stub_address = stub_address.add(INSTRUCTION_SIZE * 2)
        
        # "mov x0, #0x0000\n" // KEXT flag.
        stub_address = assemble_opcode(assembler, stub_address, "mov x0,#0x{}".format(kext_index))

        #fill first arg of sanitizer_cov_trace_pc with address of patched instrction.(before aslr/noslid)
        if USE_UNSLIDE:
            assembly_instructions = generate_assembly_instructions(str(patch_address))
            for inst in assembly_instructions:
                stub_address = assemble_opcode(assembler, stub_address, str(inst))
            
        # "bl sanitizer_cov_trace_pc"
        # "bl pop_regs"
        # "ldr x30, [sp], #0x10"
        stub_address =  stub_address.add(INSTRUCTION_SIZE * 3)

        if needs_fix:
            # so we don't need to get our hands dirty.
            # the ghidra assembler generates correct opcode and fix the address 
            # read MoreInfo.md, we don't instrument this anymore.
            # stub_address = assemble_opcode(assembler, stub_address, original_inst)
            pass
        else:
            # write original opcode
            clear_address(stub_address, INSTRUCTION_SIZE)
            memory.setBytes(stub_address, original_opcode)
            stub_address = stub_address.add(INSTRUCTION_SIZE) 

        stub_address = assemble_opcode(assembler, stub_address, jump_back_instruction)

        return stub_address

def bb_start_address(basic_block):
    start = None
    ranges = basic_block.getAddressRanges()
    while ranges.hasNext():
        r = ranges.next()
        r_min = r.getMinAddress()
        start = "0x%s" % str(r_min)
        break
    return start

# find correct inst to patch or skip and return original opcode
def find_correct_inst_or_skip_return_original(block):

    patch_address = None
    index = 0
    listing = currentProgram.getListing() # type: ignore
    instructions = listing.getInstructions(block, True)
    bb_addr = toAddr(bb_start_address(block)) # type: ignore
    
    for inst in instructions:
        if check_nonrelative(inst):
            patch_address = bb_addr.add(index * INSTRUCTION_SIZE)
            original_opcode  = get_opcode_by_address(patch_address)
            return [patch_address, original_opcode, False]
        index = index + 1

    return [None, None, False]

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
    
def find_thunk(pishi_start_address, pishi_end_address):
    
    thunk = [95, 36, 3, -43, -2, 15, 31, -8]
    opcodes = jarray.zeros(INSTRUCTION_SIZE * 2 ,"b") # it took me one day to find out about jarray.
    memory = currentProgram.getMemory()
    pointer = toAddr(pishi_start_address)
    end = toAddr(pishi_end_address)
    memory.getBytes(pointer, opcodes)

    while pointer < end:
        memory.getBytes(pointer, opcodes)
        if list(opcodes) == thunk:
            return pointer.add(INSTRUCTION_SIZE)
        pointer = pointer.add(INSTRUCTION_SIZE)


def kext_index_to_kext_flag(kext_index):
    if kext_index == 0:
        return 0
    if kext_index == 1:
        return 1
    if kext_index > 16: # we use one mov instruction, the max immediate values on aarch64 is 16 bit.
        print("mex number of suported KEXTs")
        exit(0)
    else:
        return  1 << kext_index - 1

def main():

    targets = target_function()
   
    stub_gen = Instruction()

    pishi_start_address, pishi_end_address = get_kext("Kcov.macOS.Pishi")
    if pishi_start_address == None or pishi_end_address == None:
        print("could not find Kcov.macOS.Pishi")
        exit(0)
        
    current_address = find_thunk(pishi_start_address, pishi_end_address)
    if not current_address:
        print("Could not find _thunks.")
        exit(0)

    print("thunk address {}".format(current_address))

    all_basic_blocks = get_basic_blocks(targets) # type: ignore #all kext for iosurface 
    if not all_basic_blocks:
        print("all_basic_blocks is empty check if start_address and end_address is correct.")
    
    bb_index = 0
    for function_blocks in all_basic_blocks:
        for block in function_blocks:
            patch_address, original_opcode, needs_fix = find_correct_inst_or_skip_return_original(block)
            if patch_address == None:
                continue
            current_address = stub_gen.instrument(current_address, patch_address, original_opcode, needs_fix, bb_index, kext_index_to_kext_flag(1))
            bb_index = bb_index + 1


if __name__ == "__main__":
    main()
