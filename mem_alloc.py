import pykd
from os.path import expanduser

home = "D:\\Repos\\Heap_monitoring"
return_reg = "rax"
stack_pointer = "rsp"
arch_bits = 64
log = None


#RtlAllocateHeap(
# IN PVOID                HeapHandle,
# IN ULONG                Flags,
# IN ULONG                Size );
class handle_allocate_heap(pykd.eventHandler):
    bp_end = None
    def __init__(self):
        addr = pykd.getOffset("ntdll!RtlAllocateHeap")
        if addr is None:
            return
        self.bp_init = pykd.setBp(addr, self.enter_call_back)
        self.bp_end = None

    def enter_call_back(self):
        self.out = "RtlAllocateHeap("
        self.out += hex(pykd.reg("rcx")) + " , "
        self.out += hex(pykd.reg("rdx")) + " , "
        self.out += hex(pykd.reg("r8")) + ") = "
        if self.bp_end == None:
            disas = pykd.dbgCommand("uf ntdll!RtlAllocateHeap").split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end = pykd.setBp(pykd.expr(self.ret_addr), self.return_call_back)
        return False

    def return_call_back(self):
        log.write(self.out + hex(pykd.reg(return_reg)) + "\n")
        return False


#RtlFreeHeap(
#IN PVOID                HeapHandle,
#IN ULONG                Flags OPTIONAL,
#IN PVOID                MemoryPointer );
class handle_free_heap(pykd.eventHandler):
        bp_end = None
        def __init__(self):
                addr = pykd.getOffset("ntdll!RtlFreeHeap")
                if addr is None:
                        return
                self.bp_init = pykd.setBp(addr, self.enter_call_back)
                self.bp_end = None

        def enter_call_back(self):
                self.out = "RtlFreeHeap("
                self.out += hex(pykd.reg("rcx")) + " , "
                self.out += hex(pykd.reg("rdx")) + " , "
                self.out += hex(pykd.reg("r8")) + ") = "
                if self.bp_end == None:
                        disas = pykd.dbgCommand("uf ntdll!RtlFreeHeap").split('\n')
                        for i in disas:
                                if 'ret' in i:
                                        self.ret_addr = i.split()[0]
                                        break
                        self.bp_end = pykd.setBp(pykd.expr(self.ret_addr), self.return_call_back)
                return False

        def return_call_back(self):
                ret_val = hex(pykd.reg("al"))
                log.write(self.out + ret_val + "\n")
                return False


#RtlReAllocateHeap(
#IN PVOID                HeapHandle,
#IN ULONG                Flags,
# IN PVOID                MemoryPointer,
# IN ULONG                Size );
class handle_realloc_heap(pykd.eventHandler):
        def __init__(self):
                addr = pykd.getOffset("ntdll!RtlReAllocateHeap")
                if addr is None:
                        return
                self.bp_init = pykd.setBp(addr, self.enter_call_back)
                self.bp_end = None

        def enter_call_back(self):
                self.out = "RtlReAllocateHeap("
                self.out += hex(pykd.reg("rcx")) + " , "
                self.out += hex(pykd.reg("rdx")) + " , "
                self.out += hex(pykd.reg("r8")) + " , "
                self.out += hex(pykd.reg("r9")) + ") = "
                if self.bp_end == None:
                        disas = pykd.dbgCommand("uf ntdll!RtlReAllocateHeap").split('\n')
                        for i in disas:
                                if 'ret' in i:
                                        self.ret_addr = i.split()[0]
                                        break
                        self.bp_end = pykd.setBp(pykd.expr(self.ret_addr), self.return_call_back)
                return False

        def return_call_back(self):
                log.write(self.out + hex(pykd.reg(return_reg)) + "\n")
                return False


log = open(home + "\log.log", "w+")

try:
        pykd.reg("rax")
except:
        arch_bits = 32
        return_reg = "eax"
        stack_pointer = "esp"

handle_allocate_heap()
handle_free_heap()
handle_realloc_heap()
pykd.go()