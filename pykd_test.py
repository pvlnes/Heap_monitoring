import sys
from pykd import *

addrWF = getOffset("ntdll!RtlAllocateHeap")

print(addrWF)
print(type(addrWF))