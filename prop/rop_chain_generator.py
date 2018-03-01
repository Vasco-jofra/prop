from loaders.architecture import *
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

registers = [ \
    "rax",  "eax",   "ax",   "al",
    "rbx",  "edx",   "dx",   "dl",
    "rcx",  "ecx",   "cx",   "cl",
    "rdx",  "ebx",   "bx",   "bl",
    "rsi",  "esi",   "si",  "sil",
    "rdi",  "edi",   "di",  "dil",
    "rsp",  "esp",   "sp",  "spl",
    "rbp",  "ebp",   "bp",  "bpl",
    "r8" ,  "r8d",  "r8w",  "r8b",
    "r9" ,  "r9d",  "r9w",  "r9b",
    "r10", "r10d", "r10w", "r10b",
    "r11", "r11d", "r11w", "r11b",
    "r12", "r12d", "r12w", "r12b",
    "r13", "r13d", "r13w", "r13b",
    "r14", "r14d", "r14w", "r14b",
    "r15", "r15d", "r15w", "r15b",
]

class RopChainGenerator(object):
    def __init__(self, gadgets, mode):
        self.gadgets   = gadgets
        self.mode      = mode
        self.pack_func = "p32" if mode == MODE_32 else "p64"

        # @SEE: We will need some analysis metadata here, like registers controlled (set by the primitive analysis)
        self.register_control = set()

        self.primitive_analysis = [RegisterControlAnalyzer(self), SyscallAnalyzer(self), WriteWhatWhereAnalyzer(self)]
        self.composite_analysis = []

    def analyze(self):
        for i in self.primitive_analysis:
            i.analyze()

    def gen_python(self):
        # We must analyze first because reasons
        self.analyze()

        res = ""
        for i in self.primitive_analysis:
            res += "-----------------\n" + i.gen_python()
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
        self.pack_func     = rop_chain_gen.pack_func
        self.all_gadgets   = rop_chain_gen.gadgets
        self.good_gadgets  = None

    def gen_func(self, name, content, args = [], defaults = []):
        code  = ""
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

    def gadget_comment(self, gadget, addrs):
        return " # " + str(gadget) + " --> " + str(map(lambda x: x if 'L' != x[-1] else x[:-1], map(hex, addrs)))

class RegisterControlAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(RegisterControlAnalyzer, self).__init__(rop_chain_gen)

    def __is_clean_pop(self, gadget, res = []):
        if "pop " not in gadget[0]:
            return False, None

        operand = gadget[0].replace("pop ", "")
        res.append(operand)
        if gadget[1] == 'ret':
            return True, res
        elif "pop " in gadget[1]:
            return self.__is_clean_pop(gadget[1:], res)
        else:
            return False, None

    def analyze(self):
        """ Looks for control of registers """
        if self.good_gadgets != None:
            return self.good_gadgets

        self.good_gadgets  = {}
        for gadget, addrs in self.all_gadgets.iteritems():
            success, operands = self.__is_clean_pop(gadget)
            if success:
                self.good_gadgets[gadget] = addrs
                for i in operands:
                    self.rop_chain_gen.register_control.add(i)

        return self.good_gadgets

    def gen_python(self):
        """ Generates the python functions that are used to control the registers """
        self.analyze()

        res = ""
        for gadget, addrs in self.good_gadgets.iteritems():
            # Start stuff
            content  = "\t"
            content += 'return "".join([\n'

            # Address of the gadget
            content += "\t\t"
            content += self.pack_func + "(" + hex(addrs[0]).replace("L", "") + "),"
            content += self.gadget_comment(gadget, addrs) + "\n"

            # The values to pop
            regs = [p.replace("pop ", "") for p in gadget[:-1]]
            for reg in regs:
                content += "\t\t"
                content += self.pack_func + "(" + reg + "),"
                content += "\n"

            # End stuff
            content += "\t"
            content += "])"

            name = "set_%s" % ("_".join(regs))
            res += self.gen_func(name, content, regs)
            res += "\n"
        return res

class SyscallAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(SyscallAnalyzer, self).__init__(rop_chain_gen)

    def analyze(self):
        """ Looks for a syscall gadget """
        if self.good_gadgets != None:
            return self.good_gadgets

        self.good_gadgets  = {}
        syscall_intrs = ["int 0x80", "sysenter", "syscall"]
        for k, v in self.all_gadgets.iteritems():
            if k[0] in syscall_intrs:
                self.good_gadgets[k] = v
        return self.good_gadgets

    def gen_python(self):
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
            content += self.gadget_comment(gadget, addrs) + "\n"
            first = False

        if content != "":
            res += self.gen_func("syscall", content)
        return res


class WriteWhatWhereAnalyzer(BaseAnalysis):
    def __init__(self, rop_chain_gen):
        super(WriteWhatWhereAnalyzer, self).__init__(rop_chain_gen)

        self.max_depth = 4
        self.write_what_where_regex = re.compile("^mov.*? \[(.*)\], (.*)$")
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
            # @TODO: stuff like mov [eax], ax should be flagged as wrong and is not
            if operands["from"] in operands["to"]:
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
        self.operands     = {}
        for gadget, addrs in self.all_gadgets.iteritems():
            success, oper = self.__is_write_what_where(gadget)
            if success:
                self.good_gadgets[gadget] = addrs
                self.operands[gadget]     = oper
        return self.good_gadgets

    def gen_python(self):
        self.analyze()

        res = ""
        content = '\treturn "".join([\n'
        first = True
        for gadget in sorted(self.good_gadgets, key = len)[:10]:
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
            content += self.gadget_comment(gadget, addrs) + "\n"

        content += "\t])"

        if content != "":
            res += self.gen_func("write_what_where", content)

        return res

