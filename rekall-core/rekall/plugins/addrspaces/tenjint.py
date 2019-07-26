# Rekall Memory Forensics
# Copyright 2019 Bedrock Systems Inc. All Rights Reserved.
#
# Authors:
# Jonas Pfoh <jonas@bedrocksystems.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

from urllib.parse import urlparse
from rekall import addrspace

class TenjintAddressSpace(addrspace.BaseAddressSpace):
    """An address space for tenjint"""

    __abstract = False
    __name = "tenjint"
    order = 90
    volatile = True
    __image = True

    def __init__(self, base=None, session=None, **kwargs):
        self.as_assert(base == None, "Base passed to tenjint address space")
        import tenjint
        self.as_assert(tenjint.api.initialized, "tenjint cannot initialize outside of the QEMU address space")

        super(TenjintAddressSpace, self).__init__(base=base, session=session, **kwargs)

        self._service = tenjint.service.manager()
        self._vm = self._service.get("VirtualMachine")

    def read(self, addr, length):
        addr = int(addr)
        length = int(length)
        return self._vm.phys_mem_read(addr, length)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_mappings(self, start=0, end=2**64):
        _ = end
        yield addrspace.Run(start=0, end=self._vm.phys_mem_size, address_space=self)

    def is_valid_address(self, addr):
        if addr is None or addr >= self._vm.phys_mem_size:
            return False
        return True

