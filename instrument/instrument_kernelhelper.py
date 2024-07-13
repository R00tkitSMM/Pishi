#@author Meysam
#@category macOS.kernel

import os
import json
import jarray
import json
import os
import subprocess
import json
import pickle

from ghidra.program.model.listing import FunctionManager

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from ghidra.app.plugin.assembler import Assemblers;
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.app.util.demangler import Demangler
from ghidra.app.util.demangler.gnu import GnuDemangler


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
    'and',  'ldadd',  'stur',  'mov',
    'add',  'ldr',    'str',   'ldp', 
    'stp',   'mul',   'lsl', 
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


def get_dwarfdump(adddress):
    dSYM_path = "/Users/meysam/project/Pishi/kernels/Kernels/kernel.release.vmapple.dSYM/Contents/Resources/DWARF/kernel.release.vmapple"
    dwarfdump_command = ["dwarfdump","--lookup", "0x{}".format(str(adddress)), dSYM_path]
    print(dwarfdump_command)
    try:
        result = subprocess.check_output(dwarfdump_command, stderr=subprocess.STDOUT).encode('ascii','ignore')
        return result.splitlines()
    except subprocess.CalledProcessError as e:
        print("An error occurred:\n" + str(e))


def get_file(adddress):

    lines = get_dwarfdump(adddress)
    start_index = 0
    for line in lines:
        start_index = start_index + 1
        if "DW_TAG_subprogram" in line:
            print(line)
            break

    output_lines = []
    for line in lines[start_index:]:
        # Remove parentheses and split by space
        cleaned_line = line.replace("(", "").replace(")", "").strip()
        key_value = cleaned_line.split(" ", 1)  # Split on first space
        if len(key_value) == 2:
            output_lines.append([str(key_value[0]), str(key_value[1])])

    print(output_lines)


def get_kext(kext):
    program = currentProgram
    listing = program.getListing()
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


def get_path(pattern):

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
            if pattern in line_name:
                map_name_line.append(str(name))

    return map_name_line

def main():

    listing = currentProgram.getListing() 
    function_manager = currentProgram.getFunctionManager()
    functions = None  
    instrument_functions = []
    script_dir = os.path.dirname(os.path.abspath(__file__))

    
    map_name_line = map_name_line = get_path("/bsd/net/") # get pattern from config

    kernel_text_start, kernel_text_end = get_kext("kernel.release.vmapple")

    kc_functions = function_manager.getFunctions(True)
    comapre = []
    instrument_functions.append([str(kernel_text_start), "", "", "kernel.release.vmapple"]) 
    for function in kc_functions:
            function_address = function.getEntryPoint()
            ParameterCount = function.getParameterCount()
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
    #print(set(map_name_line)-set(comapre))
    
    with open("{}/tagged_functions.json".format(script_dir), 'w') as f:
        json.dump(instrument_functions, f)
    

if __name__ == "__main__":
    main()
