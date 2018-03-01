#!/usr/bin/python2
from utils.logger import *
from utils.color import YELLOW, NO_COLOR
from binary import *
from rop_chain_generator import *
from loaders.architecture import *

import os
import sys
import time
import distorm3

ends      = ["ret", "retf", "int", "sysenter", "syscall", "call e", "call r"] # "jmp", "call"]
blacklist = ["db", "int 3"]

def extract_gadget(pc, data, mode):
    """ Returns the gadget found with the given data """
    disasm = distorm3.Decode(pc, data, mode)

    instr_list = []
    addr_list  = []
    for d in disasm:
        addr = d[0]
        size = d[1]
        inst = d[2].lower()
        opcodes = d[3]

        ### if inst in blacklist:
        # @Performance: Needed because the above does not work as intended
        if any(True for bl in blacklist if bl in inst):
            return None, None

        instr_list.append(inst)
        addr_list.append(addr)

        ### if inst in ends:
        # @Performance: Needed because the above does not work as intended
        # (the above does exact matching and ret 0x20 or something similar does not get flagged)
        if any(True for end in ends if end in inst):
            return addr_list, instr_list

    # Did not find an end
    return None, None


def extract_gadgets(binary, depth = 10):
    """ Extracts all the gadgets that exist in the file given, and returns them in a set """

    log_info("Extracting gadgets for the binary '%s'" % binary.getFileName())
    # binary = Binary(filename)

    if binary.getArchMode() == MODE_32:
        mode = distorm3.Decode32Bits
    else:
        mode = distorm3.Decode64Bits

    for section in binary.getExecSections():
        opcodes = section['opcodes']
        vaddr   = section['vaddr']
        size    = section['size']
        offset  = section['offset']

        log_info("Extracting gadgets from the executable section 0x%x-0x%x" % (vaddr, vaddr+size))

        start_time   = time.time()
        tested_addrs = set()
        gadgets      = {}

        # @Performance: thread this
        skipped = 0
        for i in range(size):
            src_addr = vaddr+i
            src_data = opcodes[i:i+depth]

            # Check to see if we need to extract gadgets for this address
            if src_addr not in tested_addrs:
                (addrs, instrs) = extract_gadget(src_addr, src_data, mode)
            else:
                skipped += 1

            # If we got a valid gadget
            if addrs != None:
                for i, a in enumerate(addrs):
                    # I think this is needed beacause even if we start at different addrs we may end up falling
                    # in the same address due to opcode sizes
                    if a in tested_addrs:
                        break

                    tested_addrs.add(a)
                    val = tuple(instrs[i:])
                    if val in gadgets:
                        gadgets[val].append(a)
                    else:
                        gadgets[val] = [a]

        log_info("Found %d unique gadgets in %0.2f seconds at depth %d." % (len(gadgets), time.time()-start_time, depth))
        log_info("Skipped %d" % skipped) # @Cleanup: remove me

    return gadgets

def order_by_address(gadgets):
    return sorted(gadgets, key=gadgets.get)

def order_by_instr(gadgets):
    return sorted(gadgets)

def get_gadgets_as_python(gadgets):
    ordered_gadgets = order_by_instr(gadgets)
    yield "gadgets = { \\"
    for instrs in ordered_gadgets:
        yield "\t%s: %s," % (instrs, gadgets[instrs])
    yield "}"

def get_gadgets_as_text(gadgets):
    ordered_gadgets = order_by_instr(gadgets)
    for instrs in ordered_gadgets:
        yield ":%s  ---> %s" % ("; ".join(instrs), map(lambda x: x if 'L' != x[-1] else x[:-1], map(hex, gadgets[instrs])))

# =============
# MAIN
# =============
def main():
    if len(sys.argv) < 2:
        log_fatal("Please provide an argument. Usage: ./%s <binary_file>" % sys.argv[0])

    # Parsing example:
    # NO_RAW = False
    # if '--noraw' in sys.argv:
    #     NO_RAW = True
    #     idx = sys.argv.index('--noraw')
    #     del sys.argv[idx]

    binpath = os.path.join(os.getcwd(), sys.argv[1])
    binary = Binary(binpath)

    # @Cleanup: remove me
    from test_0_rops import gadgets
    # gadgets = extract_gadgets(binary)

    # for i in get_gadgets_as_text(gadgets):
    #     print i

    rop_gen = RopChainGenerator(gadgets, binary.getArchMode())
    print rop_gen.gen_python()

if __name__ == "__main__":
    main()

EXAMPLE = "TODO"