# Rekall Memory Forensics
#
# Copyright 2020 BedRock Systems, Inc.
#
# Authors:
# Sebastian Vogl <sebastian@bedrocksystems.com>
# Jonas Pfoh     <jonas@bedrocksystems.com>
#
# Derived from rekall-core/rekall/plugins/addrspaces/arm.py
#   Copyright 2015 Google Inc. All Rights Reserved.
#   Authors:
#   Michael Cohen <scudette@google.com>
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

"""An address space to read ARM64 memory images."""

import struct

from rekall import addrspace
from rekall.plugins.addrspaces import intel


class Arm64PagedMemory(addrspace.PagedReader):
    """An address space to read virtual memory on ARM64 systems."""
    # The following are some masks we will need and pre-calculate.

    _4k_base_mask = (1 << 48) - 1
    _4k_vaddr_mask_l0 = (1 << 48) - 1
    _4k_vaddr_mask_l1_table = (1 << 39) - 1
    _4k_vaddr_mask_l1_block = (1 << 31) - 1
    _4k_vaddr_mask_l2_table = (1 << 30) - 1
    _4k_vaddr_mask_l2_block = (1 << 21) - 1
    _4k_vaddr_mask_l3_block = (1 << 21) - 1

    def __init__(self, name=None, dtb=None, **kwargs):
        super(Arm64PagedMemory, self).__init__(**kwargs)

        if not self.base:
            raise TypeError("No base Address Space")

        # If the underlying address space already knows about the dtb we use it.
        self.dtb = dtb or self.session.GetParameter("dtb")

        if not self.dtb != None:
            raise TypeError("No valid DTB specified. Try the find_dtb"
                            " plugin to search for the dtb.")
        self.name = (name or 'Kernel AS') + "@%#x" % self.dtb

        # Clear the bottom 14 bits from the TTBR.
        self.dtb &= 0xfffffffff000

    def read_long_phys(self, addr):
        """Read an unsigned 64-bit integer from physical memory.

        Note this always succeeds - reads outside mapped addresses in the image
        will simply return 0.
        """
        string = self.base.read(addr, 8)
        return struct.unpack("<Q", string)[0]

    def vtop(self, vaddr):
        """Translates virtual addresses into physical offsets.

        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.

        This function is simply a wrapper around describe_vtop() which does all
        the hard work. You probably never need to override it.
        """
        vaddr = int(vaddr)

        collection = self.describe_vtop(
            vaddr, intel.PhysicalAddressDescriptorCollector(self.session))

        return collection.physical_address

    def describe_vtop(self, vaddr, collection=None):
        return self._describe_vtop_4k(vaddr, collection)

    def _describe_vtop_4k(self, vaddr, collection=None):
        if collection is None:
            collection = intel.DescriptorCollection(self.session)

        # L0
        l0_descriptor_addr = (self.dtb + (((vaddr & self._4k_vaddr_mask_l0) >> 39) * 8))
        l0_descriptor = self.read_long_phys(l0_descriptor_addr)
        collection.add(intel.AddressTranslationDescriptor,
                       object_name="l0 descriptor",
                       object_value=l0_descriptor,
                       object_address=l0_descriptor_addr)

        l0_descriptor_type = l0_descriptor & 0b11
        # L0 descriptor must point to a table
        if l0_descriptor_type != 0b11:
            collection.add(intel.InvalidAddress, "Invalid L0 descriptor")
            return collection

        # L1
        l1_descriptor_addr = ((l0_descriptor & 0xfffffffff000) + 
                              (((vaddr & self._4k_vaddr_mask_l1_table) >> 30) * 8))
        l1_descriptor = self.read_long_phys(l1_descriptor_addr)
        collection.add(intel.AddressTranslationDescriptor,
                       object_name="l1 descriptor",
                       object_value=l1_descriptor,
                       object_address=l1_descriptor_addr)

        l1_descriptor_type = l1_descriptor & 0b11
        if not (l1_descriptor_type & 0x1):
            collection.add(intel.InvalidAddress, "Invalid L1 descriptor")
            return collection

        # l1_descriptor points to a block
        if l1_descriptor_type == 0b01:
            address = (l1_descriptor & 0xffffc0000000) | (vaddr & self._4k_vaddr_mask_l1_block)

            collection.add(intel.PhysicalAddressDescriptor, address=(address))
            return collection

        # L2
        l2_descriptor_addr = ((l1_descriptor & 0xfffffffff000) +
                              (((vaddr & self._4k_vaddr_mask_l2_table) >> 21) * 8))
        l2_descriptor = self.read_long_phys(l2_descriptor_addr)
        collection.add(intel.AddressTranslationDescriptor,
                       object_name="l2 descriptor",
                       object_value=l2_descriptor,
                       object_address=l2_descriptor_addr)

        l2_descriptor_type = l2_descriptor & 0b11
        if not (l2_descriptor_type & 0x1):
            collection.add(intel.InvalidAddress, "Invalid L2 descriptor")
            return collection

        # l2_descriptor points to a block
        if l2_descriptor_type == 0b01:
            address = (l2_descriptor & 0xffffffe00000) | (vaddr & self._4k_vaddr_mask_l2_block)

            collection.add(intel.PhysicalAddressDescriptor, address=(address))
            return collection

        # L3
        l3_descriptor_addr = ((l2_descriptor & 0xfffffffff000) +
                              (((vaddr & self._4k_vaddr_mask_l3_block) >> 12) * 8))
        l3_descriptor = self.read_long_phys(l3_descriptor_addr)
        collection.add(intel.AddressTranslationDescriptor,
                       object_name="l3 descriptor",
                       object_value=l3_descriptor,
                       object_address=l3_descriptor_addr)

        l3_descriptor_type = l3_descriptor & 0b11
        if not (l3_descriptor_type & 0x1):
            collection.add(intel.InvalidAddress, "Invalid L3 descriptor")
            return collection

        address = (l3_descriptor & 0xfffffffff000) | (vaddr & 0xfff)

        collection.add(intel.PhysicalAddressDescriptor, address=(address))
        return collection

    def page_fault_handler(self, descriptor, vaddr):
        """A placeholder for handling page faults."""
        _ = descriptor, vaddr
        return None

    def get_mappings(self, start=0, end=2**64):
        """Generate all valid addresses.

        Note that ARM requires page table entries for large sections to be
        duplicated (e.g. a supersection first_level_descriptor must be
        duplicated 16 times). We don't actually check for this here.
        """
        vaddr = 0
        raise RuntimeError("NO NO")
        while vaddr < end:
            l1_descriptor = self.read_long_phys(self.dtb | (
                (vaddr & self.table_index_mask) >> 18))

            l1_descriptor_type = l1_descriptor & 0b11

            # Page is invalid, skip the entire range.
            if l1_descriptor_type == 0b00:
                vaddr += 1 << 20
                continue

            if l1_descriptor_type == 0b10:
                # A valid super section is 16mb (1<<24) large.
                if l1_descriptor & self.super_section_mask:
                    yield addrspace.Run(
                        start=vaddr,
                        end=vaddr + (1 << 24),
                        file_offset=(l1_descriptor &
                                     self.super_section_base_address_mask),
                        address_space=self.base)

                    vaddr += 1 << 24
                    continue

                # Regular sections is 1mb large.
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 20),
                    file_offset=l1_descriptor & self.section_base_address_mask,
                    address_space=self.base)
                vaddr += 1 << 20
                continue

            # Coarse page table contains a secondary fetch summing up to 1Mb.
            if l1_descriptor_type == 0b01:
                for x in self._generate_coarse_page_table_addresses(
                        vaddr, l1_descriptor &
                        self.coarse_page_table_base_address_mask):
                    yield x

                vaddr += 1 << 20
                continue

            raise RuntimeError("Unreachable")

    def _generate_coarse_page_table_addresses(self, base_vaddr,
                                              coarse_page_base):
        vaddr = base_vaddr
        while vaddr < base_vaddr + (1 << 20):
            l2_addr = (coarse_page_base |
                       (vaddr & self.l2_table_index_mask) >> 10)

            l2_descriptor = self.read_long_phys(l2_addr)
            l2_descriptor_type = l2_descriptor & 0b11

            # 64kb Large (coarse) page table.
            if l2_descriptor_type == 0b01:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 16),
                    file_offset=(l2_descriptor &
                                 self.large_page_base_address_mask),
                    address_space=self.base)
                vaddr += 1 << 16
                continue

            # 4kb small page.
            if l2_descriptor_type == 0b10 or l2_descriptor_type == 0b11:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 12),
                    file_offset=(l2_descriptor &
                                 self.small_page_base_address_mask),
                    address_space=self.base)
                vaddr += 1 << 12
                continue

            # Invalid page.
            if l2_descriptor_type == 0b00:
                vaddr += 1 << 10
                continue

            raise RuntimeError("Unreachable")


    def end(self):
        return (2 ** 64) - 1

    def __eq__(self, other):
        return (super(Arm64PagedMemory, self).__eq__(other) and
                self.dtb == other.dtb and self.base == other.base)
