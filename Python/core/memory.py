from pymem import Pymem
from pymem.process import module_from_name, list_processes
from ctypes import windll
from .console import pink, reset, success, info




def get_max_privileges() -> bool:
    """
    Enable all available privileges on the current process token.
    """
    import win32api
    import win32security
    import win32con

    try:
        h_proc = win32api.GetCurrentProcess()
        h_token = win32security.OpenProcessToken(
            h_proc,
            win32con.TOKEN_READ | win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES,
        )

        privileges = win32security.GetTokenInformation(h_token, win32security.TokenPrivileges)
        new_privs = [(luid, win32con.SE_PRIVILEGE_ENABLED) for luid, _ in privileges]

        win32security.AdjustTokenPrivileges(h_token, False, new_privs)
        win32api.CloseHandle(h_token)
        return True
    except Exception:
        return False

def get_raw_processes():
    return [[
        i.cntThreads, i.cntUsage, i.dwFlags, i.dwSize,
        i.pcPriClassBase, i.szExeFile, i.th32DefaultHeapID,
        i.th32ModuleID, i.th32ParentProcessID, i.th32ProcessID
    ] for i in list_processes()]


def simple_get_processes():
    return [{"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]}
            for i in get_raw_processes()]


# -- Memory ------------------------------------------------------------

class Memory:
    """
    Usage:
        mem = Memory()
        mem.attach("notepad.exe")

        val = mem.read(addr, "int")        # read<int>
        mem.write(addr, 3.14, "float")     # write<float>

        raw = mem.read(addr, "bytes", size=16)
        mem.write(addr, b"\\xDE\\xAD", "bytes")

        s = mem.read(addr, "str", size=32)
        mem.write(addr, "hello", "str")
    """

    PROCESS_ACCESS = 0x1038

    _TYPE_MAP = {
        "int":       ("read_int",       "write_int"),
        "int32":     ("read_int",       "write_int"),
        "uint":      ("read_uint",      "write_uint"),
        "uint32":    ("read_uint",      "write_uint"),
        "short":     ("read_short",     "write_short"),
        "int16":     ("read_short",     "write_short"),
        "ushort":    ("read_ushort",    "write_ushort"),
        "uint16":    ("read_ushort",    "write_ushort"),
        "long":      ("read_long",      "write_long"),
        "longlong":  ("read_longlong",  "write_longlong"),
        "int64":     ("read_longlong",  "write_longlong"),
        "ulong":     ("read_ulong",     "write_ulong"),
        "ulonglong": ("read_ulonglong", "write_ulonglong"),
        "uint64":    ("read_ulonglong", "write_ulonglong"),
        "float":     ("read_float",     "write_float"),
        "double":    ("read_double",    "write_double"),
        "bool":      ("read_bool",      "write_bool"),
        "char":      ("read_char",      "write_char"),
        "uchar":     ("read_uchar",     "write_uchar"),
    }

    def __init__(self):
        self.pm = Pymem()
        self.handle = None
        self.pid: int = -1
        self.base_addr: int | None = None
        self.process_name: str | None = None

    # -- attach / detach --------------------------------------------------------
    # Opens handles for the target process for R/W

    def attach(self, process_name: str) -> bool:
        for proc in simple_get_processes():
            if proc["Name"] == process_name:
                self.pid = proc["ProcessId"]
                self.pm.open_process_from_id(self.pid)
                self.handle = windll.kernel32.OpenProcess(
                    self.PROCESS_ACCESS, False, self.pid
                )
                self.process_name = process_name

                for module in self.pm.list_modules():
                    if module.name == process_name:
                        self.base_addr = module.lpBaseOfDll
                        break

                print(f" [{pink}+{reset}] Attached to '{process_name}' (PID {self.pid})")
                if self.base_addr is not None:
                    print(f" [{pink}+{reset}] Base address: {self.base_addr:#x}")
                return True

        print(f" [{pink}!{reset}] Process '{process_name}' not found.")
        return False

    def detach(self) -> None:
        if self.handle:
            windll.kernel32.CloseHandle(self.handle)
        if self.pm.process_handle:
            self.pm.close_process()
        print(f" [{pink}+{reset}] Detached from '{self.process_name}' (PID {self.pid})")
        self.handle = None
        self.pid = -1
        self.base_addr = None
        self.process_name = None

    def get_base_address(self) -> int | None:
        return self.base_addr

    # -- read -------------------------------------------------------------------

    def read(self, address: int, type_name: str = "int", *, size: int = 0):
        """
        type_name:
            "int" / "uint" / "short" / "ushort" / "long" / "longlong"
            "ulong" / "ulonglong" / "float" / "double" / "bool"
            "char" / "uchar"
            "bytes"   — reads *size* raw bytes
            "str"     — reads a string of *size* length
            "ptr"     — dereferences an 8-byte pointer (64-bit)

        Aliases: "int32", "uint32", "int16", "uint16", "int64", "uint64"
        """
        if type_name == "bytes":
            return self.pm.read_bytes(address, size)
        if type_name == "str":
            return self.pm.read_string(address, size or 50)
        if type_name == "ptr":
            return int.from_bytes(self.pm.read_bytes(address, 8), "little")

        entry = self._TYPE_MAP.get(type_name)
        if entry is None:
            raise ValueError(f"Unknown type '{type_name}'. "
                             f"Valid: {', '.join(sorted(set(self._TYPE_MAP) | {'bytes','str','ptr'}))}")
        return getattr(self.pm, entry[0])(address)

    # -- write ------------------------------------------------------------------

    def write(self, address: int, value, type_name: str = "int") -> bool:
        """

        Accepts the same type_name strings as read().

        """
        try:
            if type_name == "bytes":
                self.pm.write_bytes(address, value, len(value))
                return True
            if type_name == "str":
                self.pm.write_string(address, value)
                return True
            if type_name == "ptr":
                self.pm.write_bytes(address, value.to_bytes(8, "little"), 8)
                return True

            entry = self._TYPE_MAP.get(type_name)
            if entry is None:
                raise ValueError(f"Unknown type '{type_name}'.")
            getattr(self.pm, entry[1])(address, value)
            return True
        except Exception:
            return False

    # -- allocation ------------------------------------------------------

    def allocate(self, size: int) -> int:
        return self.pm.allocate(size)

    def free(self, address: int) -> None:
        self.pm.free(address)

    # -- context --------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.detach()
