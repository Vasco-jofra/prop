#!/usr/bin/python2
from utils.logger import *
from utils.color import YELLOW, NO_COLOR
from binary import *
from rop_chain_generator import *
from loaders.architecture import *

import os
import argparse
import sys
import time
import distorm3

class Prop(object):
    def __init__(self, binpath, depth=10):
        self.ends      = ["ret", "retf", "int ", "sysenter", "syscall", "call e", "call r"] # "jmp", "call"]
        self.blacklist = ["db", "int 3"]

        self.binary = Binary(binpath)
        self.gadgets = {}

        self.extract_gadgets(depth=depth)

    def _extract_gadget(self, pc, data, mode):
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
            if any(True for bl in self.blacklist if bl in inst):
                return None, None

            instr_list.append(inst)
            addr_list.append(addr)

            ### if inst in ends:
            # @Performance: Needed because the above does not work as intended
            # (the above does exact matching and ret 0x20 or something similar does not get flagged)
            if any(True for end in self.ends if end in inst):
                return addr_list, instr_list

        # Did not find an end
        return None, None


    def extract_gadgets(self, depth):
        """ Extracts all the gadgets that exist in the file given, and returns them in a set """

        log_info("Extracting gadgets for the binary '%s'" % self.binary.getFileName())
        # binary = Binary(filename)

        if self.binary.getArchMode() == MODE_32:
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        for section in self.binary.getExecSections():
            opcodes = section['opcodes']
            vaddr   = section['vaddr']
            size    = section['size']
            offset  = section['offset']

            log_info("Extracting gadgets from the executable section 0x%x-0x%x" % (vaddr, vaddr+size))

            start_time   = time.time()
            tested_addrs = set()

            # @Performance: thread this
            skipped = 0
            for i in range(size):
                src_addr = vaddr+i
                src_data = opcodes[i:i+depth]

                # Check to see if we need to extract gadgets for this address
                if src_addr not in tested_addrs:
                    (addrs, instrs) = self._extract_gadget(src_addr, src_data, mode)
                else:
                    skipped += 1

                # If we got a valid gadget
                if addrs != None:
                    for i, a in enumerate(addrs):
                        # I think this is needed because even if we start at different addrs we may end up falling
                        # in the same address due to opcode sizes
                        if a in tested_addrs:
                            break

                        tested_addrs.add(a)
                        val = tuple(instrs[i:])
                        if val in self.gadgets:
                            self.gadgets[val].append(a)
                        else:
                            self.gadgets[val] = [a]

            log_info("Found %d unique gadgets in %0.2f seconds at depth %d." % (len(self.gadgets), time.time()-start_time, depth))
            log_info("Skipped %d" % skipped) # @Cleanup: remove me

        return self.gadgets

    def order_by_address(self):
        return sorted(self.gadgets, key=self.gadgets.get)

    def order_by_instr(self):
        return sorted(self.gadgets)

    def get_gadgets_as_python(self):
        ordered_gadgets = self.order_by_instr()
        yield "gadgets = { \\"
        for instrs in ordered_gadgets:
            yield "\t%s: %s," % (instrs, self.gadgets[instrs])
        yield "}"

    def get_gadgets_as_text(self):
        ordered_gadgets = self.order_by_instr()
        for instrs in ordered_gadgets:
            yield "%s  ---> %s" % ("; ".join(instrs), map(lambda x: x if 'L' != x[-1] else x[:-1], map(hex, self.gadgets[instrs])))


def exit_with_msg(msg):
    print "[ERROR] %s" % msg
    exit(-1)

# =============
# MAIN
# =============
def main():
    parser = argparse.ArgumentParser(description = 'Props to the boys.')
    parser.add_argument('binary_path', help='The binary path of the file to be analyzed')
    parser.add_argument('-d', '--depth', help='Gadget search depth', type=int, default = 10)
    parser.add_argument('-t', '--text_gadgets', action="store_true", help='output gadgets in text format (default)')
    parser.add_argument('-p', '--python_gadgets', action="store_true", help='output gadgets as a python dictionary')
    parser.add_argument('-s', '--silent', action="store_true", help='no gadgets output, just some info')
    parser.add_argument('-c', '--code', action="store_true", help='output interesting gadgets found as python functions')

    args = parser.parse_args()

    prop    = Prop(args.binary_path, depth=args.depth)
    rop_gen = RopChainGenerator(prop)

    if args.code == True:
        print rop_gen.gen_python()
    elif args.python_gadgets:
        for i in prop.get_gadgets_as_python():
            print i
    elif not args.silent:
        for i in prop.get_gadgets_as_text():
            print i


if __name__ == "__main__":
    main()
