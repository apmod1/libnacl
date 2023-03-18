
# This notice is included to comply with the terms of the Apache License.
# This file has been modified by Apurva Mody.
# Some of the modified contents in this file can be found in the libnacl/bindings directory


# -*- coding: utf-8 -*-
"""
Wrap libsodium routines
"""
# pylint: disable=C0103
# Import python libs
import ctypes
import sys
import os

__SONAMES = (23, 18, 17, 13, 10, 5, 4)


def _get_nacl():
    """
    Locate the nacl c libs to use
    """
    # Import libsodium
    if sys.platform.startswith("win"):
        try:
            return ctypes.cdll.LoadLibrary("libsodium")
        except OSError:
            pass
        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary("libsodium-{0}".format(soname_ver))
            except OSError:
                pass
        msg = "Could not locate nacl lib, searched for libsodium"
        raise OSError(msg)
    elif sys.platform.startswith("darwin"):
        try:
            return ctypes.cdll.LoadLibrary("libsodium.dylib")
        except OSError:
            pass
        try:
            libidx = __file__.find("lib")
            if libidx > 0:
                libpath = __file__[0: libidx + 3] + "/libsodium.dylib"
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            msg = "Could not locate nacl lib, searched for libsodium"
            raise OSError(msg)
    else:
        try:
            return ctypes.cdll.LoadLibrary("libsodium.so")
        except OSError:
            pass
        try:
            return ctypes.cdll.LoadLibrary("/usr/local/lib/libsodium.so")
        except OSError:
            pass
        try:
            libidx = __file__.find("lib")
            if libidx > 0:
                libpath = __file__[0: libidx + 3] + "/libsodium.so"
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass

        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary("libsodium.so.{0}".format(soname_ver))
            except OSError:
                pass
        try:
            # fall back to shipped libsodium, trust os version first
            libpath = os.path.join(os.path.dirname(__file__), "libsodium.so")
            return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass
        msg = "Could not locate nacl lib, searched for libsodium.so, "
        for soname_ver in __SONAMES:
            msg += "libsodium.so.{0}, ".format(soname_ver)
        raise OSError(msg)


# Don't load libnacl if we are in sphinx
if not "sphinx" in sys.argv[0]:
    nacl = _get_nacl()
    print(nacl)
    DOC_RUN = False
else:
    nacl = None
    DOC_RUN = True
