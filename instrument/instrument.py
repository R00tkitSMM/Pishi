#@author Meysam
#@category macOS.kernel
import os
import json
import jarray
import json
import os

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from ghidra.app.script import GhidraScript
from ghidra.app.plugin.assembler import Assemblers;
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit

push_regs = """nop
sub sp,sp,#+0x100
str xzr,[sp,#+0xf8]
str x29,[sp,#+0xe8]
str x28,[sp,#+0xe0]
str x27,[sp,#+0xd8]
str x26,[sp,#+0xd0]
str x25,[sp,#+0xc8]
str x24,[sp,#+0xc0]
str x23,[sp,#+0xb8]
str x22,[sp,#+0xb0]
str x21,[sp,#+0xa8]
str x20,[sp,#+0xa0]
str x19,[sp,#+0x98]
str x18,[sp,#+0x90]
str x17,[sp,#+0x88]
str x16,[sp,#+0x80]
str x15,[sp,#+0x78]
str x14,[sp,#+0x70]
str x13,[sp,#+0x68]
str x12,[sp,#+0x60]
str x11,[sp,#+0x58]
str x10,[sp,#+0x50]
str x9,[sp,#+0x48]
str x8,[sp,#+0x40]
str x7,[sp,#+0x38]
str x6,[sp,#+0x30]
str x5,[sp,#+0x28]
str x4,[sp,#+0x20]
str x3,[sp,#+0x18]
str x2,[sp,#+0x10]
str x1,[sp,#+0x8]
str x0,[sp]
sub sp, sp,#+0x50
ret"""

pop_regs= """nop
add sp, sp, #0x50
ldr xzr,[sp, #0xf8]
ldr x29,[sp, #0xe8]
ldr x28,[sp, #0xe0]
ldr x27,[sp, #0xd8]
ldr x26,[sp, #0xd0]
ldr x25,[sp, #0xc8]
ldr x24,[sp, #0xc0]
ldr x23,[sp, #0xb8]
ldr x22,[sp, #0xb0]
ldr x21,[sp, #0xa8]
ldr x20,[sp, #0xa0]
ldr x19,[sp, #0x98]
ldr x18,[sp, #0x90]
ldr x17,[sp, #0x88]
ldr x16,[sp, #0x80]
ldr x15,[sp, #0x78]
ldr x14,[sp, #0x70]
ldr x13,[sp, #0x68]
ldr x12,[sp, #0x60]
ldr x11,[sp, #0x58]
ldr x10,[sp, #0x50]
ldr x9,[sp, #0x48]
ldr x8,[sp, #0x40]
ldr x7,[sp, #0x38]
ldr x6,[sp, #0x30]
ldr x5,[sp, #0x28]
ldr x4,[sp, #0x20]
ldr x3,[sp, #0x18]
ldr x2,[sp, #0x10]
ldr x1,[sp, #0x8]
ldr x0,[sp]
add sp, sp, #0x100
ret"""

INSTRUCTION_SIZE = 4

def assemble_opcode_list(assembler, address, opcodes):
     asmcode = opcodes.splitlines()
     assembler.assemble(address, asmcode)
     return address.add(len(asmcode) * INSTRUCTION_SIZE) # size of each inst 


def generate_assembly_instructions(x64_number):
    if not isinstance(x64_number, str) or len(x64_number) > 16:
        raise ValueError("Input must be a 64-bit hexadecimal number as a string, e.g., 'fffffffffffffffe'")
    
    # Pad the hexadecimal number to ensure it is 16 characters long
    hex_number = x64_number.zfill(16)
    
    # Extract 16-bit segments
    segments = [hex_number[i:i+4] for i in range(0, len(hex_number), 4)]
    
    # Generate assembly instructions

    instructions = []
    instructions.append("mov x0,#0x{}".format(segments[3]))
    instructions.append("movk x0,#0x{},LSL #16".format(segments[2]))
    instructions.append("movk x0,#0x{},LSL #32".format(segments[1]))
    instructions.append("movk x0,#0x{},LSL #48".format(segments[0]))
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

def addresss_to_file_offset(address):
    mem = currentProgram.getMemory() # type: ignore
    sourceinfo = mem.getAddressSourceInfo(address)
    return sourceinfo.getFileOffset()


def do_function_basic_blocks(function):
    basic_blocks = []
    bm = BasicBlockModel(currentProgram) # type: ignore
    monitor = ConsoleTaskMonitor()
    blocks = bm.getCodeBlocksContaining(function.getBody(), monitor)

    while blocks.hasNext():
        bb = blocks.next()
        basic_blocks.append(bb)

    return basic_blocks

def get_basic_blocks(section_start, section_end):
    function_manager = currentProgram.getFunctionManager() # type: ignore
    functions = function_manager.getFunctions(True)
    # Iterate over the functions and print those within the address range
    all_basic_blocks = []
    for function in functions:
        function_address = function.getEntryPoint()
        if function_address:
            if section_start <= function_address <= section_end:
                bb_addresses = do_function_basic_blocks(function)
                all_basic_blocks.append(bb_addresses)
            
    return all_basic_blocks

def clear_address(address, length):
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(address)
    if code_unit:
        listing.clearCodeUnits(address, address.add(length - 1), False)

class Instruction(GhidraScript):
    def instrument(self, stub_address, patch_address, original_inst, needs_fix, index):

        #print("patch address: 0x{}".format(str(patch_address)))
        #print("original_opcode  {}".format(str(original_opcode)))
        print(index)


         # get orignal instruction before patch.
        jump_back_instruction = "b {}".format("meysam_return_number_" + str(index)) # Change this to your desired instruction

        original_opcode = jarray.zeros(INSTRUCTION_SIZE,"b")
        print("patch_address {}\n".format(patch_address))
        memory = currentProgram.getMemory()
        memory.getBytes(patch_address, original_opcode)


        assembler = Assemblers.getAssembler(currentProgram) # type: ignore
        create_label(stub_address, "meysam_stub_number_" + str(index))
        create_label(patch_address.add(INSTRUCTION_SIZE), "meysam_return_number_" + str(index))

       

        # Patch the BB to jump to out stub_address# label 
        patched_instruction = "b {}".format("meysam_stub_number_" + str(index)) # Change this to your desired instruction
        assemble_opcode(assembler, patch_address, patched_instruction)

        # "str x30, [sp, #-0x10]!"
        # "bl push_regs"
        stub_address = stub_address.add(INSTRUCTION_SIZE * 2)

        # fill first arg of sanitizer_cov_trace_pc with address of patched instrction.(before aslr/noslid)
        assembly_instructions = generate_assembly_instructions(str(patch_address))
        for inst in assembly_instructions:
            stub_address = assemble_opcode(assembler, stub_address, str(inst))

        # "bl sanitizer_cov_trace_pc"
        # "bl pop_regs"
        # "ldr x30, [sp], #0x10"
        stub_address =  stub_address.add(INSTRUCTION_SIZE * 3)

        if needs_fix:
            # TODO: if needs fix use assemble_opcode, it will disasm/asm function the opcode for us,
            # so we don't need to get our hands dirty.
            # the ghidra assembler generates correct opcode and fix the address 
            # stub_address = assemble_opcode(assembler, stub_address, original_inst)
            pass
        else:
            # write original opcode
            clear_address(stub_address, INSTRUCTION_SIZE)
            # print("original_opcode{}".format(original_opcode))
            memory.setBytes(stub_address, original_opcode)
            stub_address = stub_address.add(INSTRUCTION_SIZE) 


        stub_address = assemble_opcode(assembler, stub_address, jump_back_instruction)

        # TODO:
        # Fix address related operations in original_opcode.
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

def check_nonrelative(inst):

    Instruction = [
    'and',  'ldadd',  'stur',  'mov',
    'add',  'ldr',    'str',   'ldp', 
    'stp',  'sub',    'mul',   'lsl', 
    'lsr',  'cmp',    'tst',   'ldur', 
    'orn',  'bic',    'cmn',   'eon',
    'neg',  'adc',    'mvn',   'ana', 
    'eor',  'sbc',    'orr',   'ldset',
    'ubfx', 'msub',   'udiv',  'cmhs',
    'xtn',  'fmov',   'sxtw',  'ccmp',
    'asr',  'ldrb',   'strb',  'ldrh',
    'strh', 'xtn',    'uxtn',  'sxtw',
    'sxtb', 'sxth',   'uxth',  'uxtb',
    'sbfx', 'bfi',    'bfxil'
    ]

    for i in Instruction:
        if inst.startswith(i):
            return True
    
    return False

# find correct inst to patch or skip and return original opcode
def find_correct_inst_or_skip_return_original(block):

    # TODO: 
    # Ignore PAC instrctions, they are context aware, so they depend on current address.
    # Find non relative instrction, e.g mov, add, sub ,... return its address + orignal opcode
    # Find relative instrctions e.g ( not call ) return needs to fix then return its address + orignal opcode
    # should I instrument one instrction size, basic blocks? like "B"
    # we don't need to worry about indirect jmp or call with pac any of them use mov inst so we can easily replace it. so they are already covered. 
    
    patch_address = None
    index = 0
    listing = currentProgram.getListing() # type: ignore
    instructions = listing.getInstructions(block, True)
    bb_addr = toAddr(bb_start_address(block)) # type: ignore
    

    for inst in instructions:
        if check_nonrelative(str(inst)):
            patch_address = bb_addr.add(index * INSTRUCTION_SIZE)
            original_opcode  = get_opcode_by_address(patch_address)
            return [patch_address, original_opcode, False]
        index = index + 1

    return [None, None, False]

def get_config(kext):

    with open(os.path.dirname(os.path.realpath(__file__))+'/config.json', 'r') as file:
        data = json.load(file)
    
    return data[kext]

def main():

    global current_address
    stub_gen = Instruction()
    assembler = Assemblers.getAssembler(currentProgram) # type: ignore

    kext = get_config('fuzz') # TODO: get section range from file not config file.
    start_address = str(kext["start_address"])
    end_address = str(kext["end_address"])

    print("start_address {}".format(start_address))
    print("end_address {}".format(end_address))

    push_regs_address = getGlobalFunctions("_push_regs")[0].getEntryPoint()# type: ignore
    if not push_regs_address:
        print("Could not find push_regs_address")
    
    pop_regs_address = getGlobalFunctions("_pop_regs")[0].getEntryPoint() # type: ignore
    if not pop_regs_address:
        print("Could not find pop_regs_address.")

    assemble_opcode_list(assembler, push_regs_address, push_regs)
    assemble_opcode_list(assembler, pop_regs_address, pop_regs)

    # inst_stub is 5MB nop instructions. 
    current_address = getGlobalFunctions("_thunks")[0].getEntryPoint().add(INSTRUCTION_SIZE) # type: ignore
    if not current_address:
        print("Could not find _thunks.")

    all_basic_blocks = get_basic_blocks(toAddr(start_address), toAddr(end_address)) # type: ignore #all kext for iosurface 
    if not all_basic_blocks:
        print("all_basic_blocks is empty check if start_address and end_address is correct.")
    
    index = 0
    for function_blocks in all_basic_blocks:
        for block in function_blocks:
            patch_address, original_opcode, needs_fix = find_correct_inst_or_skip_return_original(block)
            if patch_address == None:
               continue
            current_address = stub_gen.instrument(current_address, patch_address, original_opcode, needs_fix, index)
            index = index +1

if __name__ == "__main__":
    main()
