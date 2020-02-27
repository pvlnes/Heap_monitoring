from pykd import *
import pykd

class handle_allocate_heap(pykd.eventHandler):
        bp_end = None
        def __init__(self):
                addr = getOffset("ntdll!RtlAllocateHeap")
                if addr is None:
                        return
                self.bp_init = pykd.setBp(addr, self.enter_call_back)
                self.bp_end = None

        def enter_call_back(self):
                print "RtlAllocateHeap called."
                if self.bp_end == None:
                        disas = pykd.dbgCommand("uf ntdll!RtlAllocateHeap").split('\n')
                        for i in disas:
                                if 'ret' in i:
                                        self.ret_addr = i.split()[0]
                                        break
                        self.bp_end = pykd.setBp(getOffset(self.ret_addr), self.return_call_back)
                return True

        def return_call_back(self, bp):
                print "RtlAllocateHeap returned."
                return False


handle_allocate_heap()
pykd.go()
