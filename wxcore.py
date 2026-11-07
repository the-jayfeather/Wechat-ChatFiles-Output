"""微信本地数据发现、进程探测、媒体密钥扫描。"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import glob
import os
import re
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------- 进程 ----------------
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.c_void_p, ctypes.c_size_t]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]

MEM_COMMIT = 0x1000
RW = (0x04, 0x08, 0x40, 0x80)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
RUN = re.compile(rb"[A-Za-z0-9]{16,}")


class _MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def weixin_pids() -> list[int]:
    """返回所有 Weixin.exe 进程 PID（主进程排前面）。"""
    import subprocess
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="gbk", errors="ignore").stdout
    rows = []
    for line in out.strip().splitlines():
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 2 and parts[0].lower() == "weixin.exe":
            try:
                rows.append(int(parts[1]))
            except ValueError:
                pass
    return rows


# ---------------- 数据目录 ----------------
def data_root() -> str | None:
    """从 %APPDATA%\\Tencent\\xwechat\\config\\*.ini 读取数据根目录。"""
    cfg = os.path.join(os.environ.get("APPDATA", ""), "Tencent", "xwechat", "config")
    if not os.path.isdir(cfg):
        return None
    for ini in glob.glob(os.path.join(cfg, "*.ini")):
        for enc in ("utf-8", "utf-8-sig", "gbk"):
            try:
                with open(ini, encoding=enc) as f:
                    p = f.read(2048).strip()
                break
            except UnicodeDecodeError:
                continue
        else:
            continue
        if p and os.path.isdir(p):
            return p
    return None


def list_accounts(root: str | None) -> list[dict]:
    if not root:
        return []
    base = os.path.join(root, "xwechat_files")
    if not os.path.isdir(base):
        return []
    out = []
    for name in sorted(os.listdir(base)):
        acc = os.path.join(base, name)
        db = os.path.join(acc, "db_storage")
        if not os.path.isdir(db):
            continue
        size = 0
        newest = 0
        for dirpath, _dirs, files in os.walk(acc):
            for f in files:
                try:
                    st = os.stat(os.path.join(dirpath, f))
                    size += st.st_size
                    newest = max(newest, st.st_mtime)
                except OSError:
                    pass
        has_msg = any(glob.glob(os.path.join(db, "message", "message_*.db")))
        out.append({"id": name, "dir": acc, "db": db, "size": size,
                    "mtime": newest, "has_msg": has_msg})
    return out


# ---------------- 图片密钥 ----------------
def _sniff(dec: bytes) -> str | None:
    if dec[:3] == b"\xff\xd8\xff":
        return "jpg"
    if dec[:4] == b"\x89PNG":
        return "png"
    if dec[:4] == b"GIF8":
        return "gif"
    if dec[:4] == b"RIFF":
        return "webp"
    if dec[:4] == b"wxgf":
        return "hevc"
    return None


def pick_dat(account_dir: str) -> tuple[bytes, str] | tuple[None, None]:
    """挑一个结构自洽的 V2 .dat 作为校验样本。"""
    best = None
    for p in glob.glob(os.path.join(account_dir, "msg", "attach", "*", "*", "Img", "*.dat")):
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                head = f.read(31)
        except OSError:
            continue
        if len(head) < 31 or head[:6] != b"\x07\x08V2\x08\x07":
            continue
        import struct
        aes_size, xor_size = struct.unpack_from("<LL", head, 6)
        aligned = aes_size + (16 if aes_size % 16 == 0 else 16 - aes_size % 16)
        if 15 + aligned + xor_size == size:
            return head[15:31], p
        best = best or (head[15:31], p)
    return best or (None, None)


def find_image_key(account_dir: str, pids: list[int], log=print) -> bytes | None:
    block, sample = pick_dat(account_dir)
    if not block:
        log("  未找到可用的 .dat 样本，跳过图片密钥")
        return None
    for pid in pids:
        h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not h:
            continue
        try:
            addr, mbi, regions = 0, _MBI(), []
            while addr < 0x7FFFFFFFFFFF:
                if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)) == 0:
                    break
                if mbi.State == MEM_COMMIT and mbi.Protect in RW and 0 < mbi.RegionSize <= 64 * 1024 * 1024:
                    regions.append((mbi.BaseAddress, mbi.RegionSize))
                nxt = addr + mbi.RegionSize
                if nxt <= addr:
                    break
                addr = nxt
            buf = ctypes.create_string_buffer(64 * 1024 * 1024)
            nread = ctypes.c_size_t(0)
            seen = set()
            for base, size in regions:
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(nread)):
                    continue
                for m in RUN.finditer(buf.raw[:nread.value]):
                    for c in {m.group(0)[:16], m.group(0)[:32][:16]}:
                        if len(c) < 16 or c in seen:
                            continue
                        seen.add(c)
                        try:
                            dec = Cipher(algorithms.AES(c), modes.ECB()).decryptor().update(block)
                        except Exception:
                            continue
                        if _sniff(dec):
                            log(f"  找到图片密钥：{c.decode()}（进程 {pid}）")
                            return c
        finally:
            k32.CloseHandle(h)
    log("  未找到图片密钥（可能微信还没加载过图片）")
    return None


def decrypt_dat(path: str, key: bytes) -> tuple[bytes, str] | tuple[None, None]:
    import struct
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 31 or data[:6] != b"\x07\x08V2\x08\x07":
        return None, None
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    aligned = aes_size + (16 if aes_size % 16 == 0 else 16 - aes_size % 16)
    if 15 + aligned > len(data):
        return None, None
    try:
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(data[15:15 + aligned])
    except Exception:
        return None, None
    if dec:
        n = dec[-1]
        if 1 <= n <= 16 and dec[-n:] == bytes([n]) * n:
            dec = dec[:-n]
    raw_end = len(data) - xor_size
    raw = data[15 + aligned:raw_end] if 15 + aligned < raw_end else b""
    tail = data[raw_end:]
    plain_tail = b""
    if tail:
        k = tail[-1] ^ 0xD9
        plain_tail = bytes(b ^ k for b in tail)
    out = dec + raw + plain_tail
    return out, _sniff(dec)


def _cache_dir() -> str:
    base = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "微信聊天记录导出器")
    os.makedirs(base, exist_ok=True)
    return base


def load_cached_image_key() -> bytes | None:
    p = os.path.join(_cache_dir(), "image_key.txt")
    try:
        with open(p, encoding="utf-8") as f:
            v = f.read().strip()
        return v.encode()[:16] if len(v) >= 16 else None
    except OSError:
        return None


def save_image_key(key: bytes) -> None:
    try:
        with open(os.path.join(_cache_dir(), "image_key.txt"), "w", encoding="utf-8") as f:
            f.write(key.decode("ascii", "ignore"))
    except OSError:
        pass