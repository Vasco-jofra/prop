from .loaders.architecture import *
import re

# self.register_control = { \
#     "rax": False,  "eax": False,   "ax": False,   "al": False,
#     "rbx": False,  "edx": False,   "dx": False,   "dl": False,
#     "rcx": False,  "ecx": False,   "cx": False,   "cl": False,
#     "rdx": False,  "ebx": False,   "bx": False,   "bl": False,
#     "rsi": False,  "esi": False,   "si": False,  "sil": False,
#     "rdi": False,  "edi": False,   "di": False,  "dil": False,
#     "rsp": False,  "esp": False,   "sp": False,  "spl": False,
#     "rbp": False,  "ebp": False,   "bp": False,  "bpl": False,
#     "r8":  False,  "r8d": False,  "r8w": False,  "r8b": False,
#     "r9":  False,  "r9d": False,  "r9w": False,  "r9b": False,
#     "r10": False, "r10d": False, "r10w": False, "r10b": False,
#     "r11": False, "r11d": False, "r11w": False, "r11b": False,
#     "r12": False, "r12d": False, "r12w": False, "r12b": False,
#     "r13": False, "r13d": False, "r13w": False, "r13b": False,
#     "r14": False, "r14d": False, "r14w": False, "r14b": False,
#     "r15": False, "r15d": False, "r15w": False, "r15b": False,
# }

registers = {
    'rax': ('rax', 'eax', 'ax', 'al', 'ah'),
    'eax': ('rax', 'eax', 'ax', 'al', 'ah'),
    'ax': ('rax', 'eax', 'ax', 'al', 'ah'),
    'al': ('rax', 'eax', 'ax', 'al', 'ah'),
    'ah': ('rax', 'eax', 'ax', 'al', 'ah'),
    'rbx': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    'ebx': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    'bx': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    'bl': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    'bh': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    'rcx': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    'ecx': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    'cx': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    'cl': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    'ch': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    'rdx': ('rdx', 'edx', 'dx', 'dl', 'dh'),
    'edx': ('rdx', 'edx', 'dx', 'dl', 'dh'),
    'dx': ('rdx', 'edx', 'dx', 'dl', 'dh'),
    'dl': ('rdx', 'edx', 'dx', 'dl', 'dh'),
    'dh': ('rdx', 'edx', 'dx', 'dl', 'dh'),
    'rsi': ('rsi', 'esi', 'si', 'sil'),
    'esi': ('rsi', 'esi', 'si', 'sil'),
    'si': ('rsi', 'esi', 'si', 'sil'),
    'sil': ('rsi', 'esi', 'si', 'sil'),
    'rdi': ('rdi', 'edi', 'di', 'dil'),
    'edi': ('rdi', 'edi', 'di', 'dil'),
    'di': ('rdi', 'edi', 'di', 'dil'),
    'dil': ('rdi', 'edi', 'di', 'dil'),
    'rsp': ('rsp', 'esp', 'sp', 'spl'),
    'esp': ('rsp', 'esp', 'sp', 'spl'),
    'sp': ('rsp', 'esp', 'sp', 'spl'),
    'spl': ('rsp', 'esp', 'sp', 'spl'),
    'rbp': ('rbp', 'ebp', 'bp', 'bpl'),
    'ebp': ('rbp', 'ebp', 'bp', 'bpl'),
    'bp': ('rbp', 'ebp', 'bp', 'bpl'),
    'bpl': ('rbp', 'ebp', 'bp', 'bpl'),
    'r8': ('r8', 'r8d', 'r8w', 'r8b'),
    'r8d': ('r8', 'r8d', 'r8w', 'r8b'),
    'r8w': ('r8', 'r8d', 'r8w', 'r8b'),
    'r8b': ('r8', 'r8d', 'r8w', 'r8b'),
    'r9': ('r9', 'r9d', 'r9w', 'r9b'),
    'r9d': ('r9', 'r9d', 'r9w', 'r9b'),
    'r9w': ('r9', 'r9d', 'r9w', 'r9b'),
    'r9b': ('r9', 'r9d', 'r9w', 'r9b'),
    'r10': ('r10', 'r10d', 'r10w', 'r10b'),
    'r10d': ('r10', 'r10d', 'r10w', 'r10b'),
    'r10w': ('r10', 'r10d', 'r10w', 'r10b'),
    'r10b': ('r10', 'r10d', 'r10w', 'r10b'),
    'r11': ('r11', 'r11d', 'r11w', 'r11b'),
    'r11d': ('r11', 'r11d', 'r11w', 'r11b'),
    'r11w': ('r11', 'r11d', 'r11w', 'r11b'),
    'r11b': ('r11', 'r11d', 'r11w', 'r11b'),
    'r12': ('r12', 'r12d', 'r12w', 'r12b'),
    'r12d': ('r12', 'r12d', 'r12w', 'r12b'),
    'r12w': ('r12', 'r12d', 'r12w', 'r12b'),
    'r12b': ('r12', 'r12d', 'r12w', 'r12b'),
    'r13': ('r13', 'r13d', 'r13w', 'r13b'),
    'r13d': ('r13', 'r13d', 'r13w', 'r13b'),
    'r13w': ('r13', 'r13d', 'r13w', 'r13b'),
    'r13b': ('r13', 'r13d', 'r13w', 'r13b'),
    'r14': ('r14', 'r14d', 'r14w', 'r14b'),
    'r14d': ('r14', 'r14d', 'r14w', 'r14b'),
    'r14w': ('r14', 'r14d', 'r14w', 'r14b'),
    'r14b': ('r14', 'r14d', 'r14w', 'r14b'),
    'r15': ('r15', 'r15d', 'r15w', 'r15b'),
    'r15d': ('r15', 'r15d', 'r15w', 'r15b'),
    'r15w': ('r15', 'r15d', 'r15w', 'r15b'),
    'r15b': ('r15', 'r15d', 'r15w', 'r15b'),
}


class RopChainGenerator(object):
    def __init__(self, prop):
        self.gadgets = prop.gadgets
        self.mode = prop.binary.getArchMode()
        self.pack_func = "p32" if self.mode == MODE_32 else "p64"

        # @SEE: We will need some analysis metadata here, like registers controlled (set by the primitive analysis)
        self.register_control = set()

        self.primitive_analysis = [RegisterControlAnalyzer(self), SyscallAnalyzer(self), WriteWhatWhereAnalyzer(self)]
        self.composite_analysis = []

    def analyze(self):
        for i in self.primitive_analysis:
            i.analyze()

    def gen_python(self, max_addrs_per_gadget):
        # We must analyze first because reasons
        self.analyze()

        res = ""
        for i in self.primitive_analysis:
            res += "####################\n" + i.gen_python(max_addrs_per_gadget)
        return res

    def controls(self, reg):
        pass

    """def ideias():
        def gen_python_call_system_syscall():
            # set eax to ...
            # set other regs to .. (might need write-what-where to write 'bin/sh')
            # call syscall
            pass
        def gen_rop_chain():
    """


### ANALYSIS
### ANALYSIS
### ANALYSIS
class BaseAnalysis(object):
    def __init__(self, rop_chain_gen):
        self.rop_chain_gen = rop_chain_gen
        self.pack_func = rop_chain_gen.pack_func
        self.all_gadgets = rop_chain_gen.gadgets
        self.good_gadgets = None

    def gen_func(self, name, content, args=None, defaults=None):
        if args is None:
            args = []
        if defaults is None:
            defaults = []

        code = ""
        code += "def %s(" % name
        for i, arg in enumerate(args):
            code += arg
            if i < len(defaults) - 1:
                code += " = " + defaults[i]
            if i != len(args) - 1:
                code += ", "
        code += "):\n"
        code += content
        code += "\n"
        return code

    def gadget_comment(self, gadget, addrs, max_addrs_per_gadget):
        return " # " + str(gadget) + " --> " + str([hex(x).strip('L') for x in addrs[:max_addrs_per_gadget]])


class RegisterControlAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(RegisterControlAnalyzer, self).__init__(rop_chain_gen)

    @staticmethod
    def __is_clean_pop(gadget):
        ERROR = (False, None)
        res = []

        if len(gadget) <= 1:
            return ERROR

        if gadget[-1] != 'ret':
            return ERROR

        for instr in gadget[:-1]:
            if "pop " not in instr:
                return ERROR

            operand = instr.split(" ", 1)[1]
            res.append(operand)

        # ignore successive pops to the same register unless we had another pop in between
        if len(res) >= 2 and res[0] == res[1]:
            return ERROR

        return True, res

    def analyze(self):
        """ Looks for control of registers """
        if self.good_gadgets != None:
            return self.good_gadgets

        self.good_gadgets = {}
        for gadget, addrs in self.all_gadgets.iteritems():
            success, operands = self.__is_clean_pop(gadget)
            if success:
                self.good_gadgets[gadget] = addrs
                for i in operands:
                    # Add control to the register and all sub registers
                    reg_fam = registers[i]
                    regs_to_add = reg_fam[reg_fam.index(i):]
                    for reg in regs_to_add:
                        self.rop_chain_gen.register_control.add(reg)

        return self.good_gadgets

    def gen_python(self, max_addrs_per_gadget):
        """ Generates the python functions that are used to control the registers """
        self.analyze()

        res = ""
        for gadget, addrs in self.good_gadgets.iteritems():
            # Start stuff
            content = "\t"
            content += 'return "".join([\n'

            # Address of the gadget
            content += "\t\t"
            content += self.pack_func + "(" + hex(addrs[0]).replace("L", "") + "),"
            content += self.gadget_comment(gadget, addrs, max_addrs_per_gadget) + "\n"

            # The values to pop
            regs = [p.replace("pop ", "") for p in gadget[:-1]]
            for reg in regs:
                content += "\t\t"
                content += self.pack_func + "(" + reg + "),"
                content += "\n"

            # End stuff
            content += "\t"
            content += "])"

            # remove duplicate registers from python code arguments
            non_duped_regs = []
            for r in regs:
                if r not in non_duped_regs:
                    non_duped_regs.append(r)

            name = "set_%s" % ("_".join(regs))
            res += self.gen_func(name, content, non_duped_regs)
            res += "\n"
        return res


class SyscallAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(SyscallAnalyzer, self).__init__(rop_chain_gen)

    def analyze(self):
        """ Looks for a syscall gadget """
        if self.good_gadgets != None:
            return self.good_gadgets

        self.good_gadgets = {}
        syscall_intrs = ["int 0x80", "sysenter", "syscall"]
        for k, v in self.all_gadgets.iteritems():
            if k[0] in syscall_intrs:
                self.good_gadgets[k] = v
        return self.good_gadgets

    def gen_python(self, max_addrs_per_gadget):
        self.analyze()

        res = ""
        content = ""
        first = True
        for gadget, addrs in self.good_gadgets.iteritems():
            if first == False:
                content += "\t# Other option: "
            else:
                content += "\t"
            content += "return " + self.pack_func + "(" + hex(addrs[0]).replace("L", "") + ")"
            content += self.gadget_comment(gadget, addrs, max_addrs_per_gadget) + "\n"
            first = False

        if content != "":
            res += self.gen_func("syscall", content)
        return res


class WriteWhatWhereAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(WriteWhatWhereAnalyzer, self).__init__(rop_chain_gen)

        self.max_depth = 10
        self.write_what_where_regex = re.compile(r"^mov.*? \[(.*)\], (.*)$")
        self.operands = None

    def __is_write_what_where(self, gadget):
        if len(gadget) > self.max_depth:
            return False, None

        if "mov " not in gadget[0] or gadget[-1] != 'ret':
            return False, None

        match = self.write_what_where_regex.match(gadget[0])
        if match:
            operands = {"to": match.group(1), "from": match.group(2)}
            # If we have the same register for writing and reading it's pointless
            if operands["from"] == operands["to"]:
                return False, None

            if operands["to"] not in registers:
                return False, None

            # @TODO: We may actually want to write with imediates since it may help to write a specific byte and get lucky (e.g. mov [eax], 0
            if operands["from"] not in registers:
                return False, None

            return True, operands
        else:
            return False, None

    def analyze(self):
        " Looks for write what wheres "
        if self.good_gadgets != None:
            return self.good_gadgets

        self.good_gadgets = {}
        self.operands = {}
        for gadget, addrs in self.all_gadgets.iteritems():
            success, oper = self.__is_write_what_where(gadget)
            if success:
                self.good_gadgets[gadget] = addrs
                self.operands[gadget] = oper
        return self.good_gadgets

    def gen_python(self, max_addrs_per_gadget):
        self.analyze()

        res = ""
        content = '\treturn "".join([\n'
        first = True
        for gadget in sorted(self.good_gadgets, key=len):
            addrs = self.good_gadgets[gadget]
            operands = self.operands[gadget]
            content += "\t\t"
            if operands["to"] not in self.rop_chain_gen.register_control:
                content += "# No control of 'to'  : "
            elif operands["from"] not in self.rop_chain_gen.register_control:
                content += "# No control of 'from': "
            elif len(gadget) != 2:
                content += "# Not imediate 'ret'  : "
            elif first == False:
                content += "# Other good option   : "
            else:
                first = False

            content += "return " + self.pack_func + "(" + hex(addrs[0]).replace("L", "") + "), "
            content += self.gadget_comment(gadget, addrs, max_addrs_per_gadget) + "\n"

        content += "\t])"

        if content != "":
            res += self.gen_func("write_what_where", content)

        return res
