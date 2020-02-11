# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
# Modifications made by BedRock Systems, Inc. on
# Feb 03 2020
# which modifications are (c) 2020 BedRock Systems, Inc.
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

"""The module implements the linux specific address resolution plugin."""

from builtins import str
__author__ = "Michael Cohen <scudette@gmail.com>"

import re

from rekall_lib import utils

from rekall import obj
from rekall.plugins.common import address_resolver
from rekall.plugins.linux import common

class MapModule(address_resolver.Module):
    """A module representing a memory mapping."""

class ELFModule(address_resolver.Module):
    """ELF module base class."""

class LKMModule(ELFModule):
    """A Linux kernel module."""

    def __init__(self, module, **kwargs):
        self.module = module
        super().__init__(
            name=str(module.name),
            start=module.base,
            end=module.end,
            **kwargs)

class LibModule(ELFModule):
    """A Linux shared object module."""

    def __init__(self, module, **kwargs):
        name = module.vm_file.f_path.dentry.d_name.name.dereference()
        if name == None:
            raise ValueError("missing module name")
        self.module = module
        self.full_name = str(name)
        super().__init__(
            name=LinuxAddressResolver.NormalizeModuleName(self.full_name),
            start=module.vm_start,
            end=module.vm_end,
            **kwargs)

class KernelModule(address_resolver.Module):
    """A Fake object which makes the kernel look like a module.

    This removes the need to treat kernel addresses any different from module
    addresses, and allows them to be resolved by this module.
    """

    def __init__(self, session=None, **kwargs):
        offset = session.GetCache("kernel_slide")
        if offset is None:
            offset = 0

        super(KernelModule, self).__init__(
            # Check if the address appears in the kernel binary.
            start=obj.Pointer.integer_to_address(
                session.profile.get_constant("_text") + offset),
            end=session.profile.get_constant("_end") + offset,
            name="linux",
            profile=session.profile,
            session=session, **kwargs)

class LinuxAddressResolver(address_resolver.AddressResolverMixin,
                           common.LinuxPlugin):
    """A Linux specific address resolver plugin."""

    # The format of a symbol name. Used by get_address_by_name().
    ADDRESS_NAME_REGEX = re.compile(
        r"(?P<deref>[*])?"              # Pointer dereference.

        r"((?P<address>0x[0-9A-Fa-f]+)|" # Alternative - Either an address, or,

        r"(?P<module>[A-Za-z_0-9\-\.\\]+)" # Module name - can include extension
                                           # (.exe, .sys)

        r"!?"                           # ! separates module name from symbol
                                        # name.

        r"(?P<symbol>[^ +-]+)?"         # Symbol name.
        r")"                            # End alternative.

        r"(?P<op> *[+-] *)?"            # Possible arithmetic operator.
        r"(?P<offset>[0-9a-fA-Fx]+)?")  # Possible hex offset.

    @staticmethod
    def NormalizeModuleName(module_name):
        if module_name is not None:
            module_name = utils.SmartUnicode(module_name)
            module_name = re.split(r"[/\\]", module_name)[-1]

            # remove extention and everything after (e.g., libc.so.2.29)
            m = re.compile("(.*)\.so(\.[0-9\.]+)?").match(module_name)
            if m:
                module_name = m.group(1)

            # remove version in filename (e.g., libc-2.29)
            m = re.compile("(.*)-[0-9]+\.[0-9]+").match(module_name)
            if m:
                module_name = m.group(1)

            return module_name

    def _EnsureInitialized(self):
        if self._initialized:
            return

        # Insert a psuedo module for the kernel
        self.AddModule(KernelModule(session=self.session))

        # Add LKMs.
        for kmod in self.session.plugins.lsmod().get_module_list():
            self.AddModule(LKMModule(kmod, session=self.session))

        task = self.session.GetParameter("process_context")

        for vma in task.mm.mmap.walk_list("vm_next"):
            try:
                mod = LibModule(vma, session=self.session)
            except ValueError:
                start = vma.vm_start
                end = vma.vm_end
                mod = MapModule(
                    name="map_%#x" % start,
                    start=start, end=end, session=self.session)
            self.AddModule(mod)

        self._initialized = True
