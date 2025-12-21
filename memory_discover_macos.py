import ctypes
import struct
import argparse
import time
import json
import sys
import subprocess

KERN_SUCCESS = 0
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 10


class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_int * VM_REGION_BASIC_INFO_COUNT_64),
    ]


def load_libc():
    return ctypes.CDLL("/usr/lib/libSystem.B.dylib")


def setup_prototypes(libc):
    libc.mach_task_self.restype = ctypes.c_uint32
    libc.task_for_pid.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    libc.task_for_pid.restype = ctypes.c_int
    libc.mach_vm_read_overwrite.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
    libc.mach_vm_read_overwrite.restype = ctypes.c_int
    libc.mach_vm_write.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32]
    libc.mach_vm_write.restype = ctypes.c_int
    libc.mach_vm_protect.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool, ctypes.c_int]
    libc.mach_vm_protect.restype = ctypes.c_int
    libc.mach_vm_region.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.POINTER(vm_region_basic_info_64), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    libc.mach_vm_region.restype = ctypes.c_int


def find_pid_by_name(name: str) -> int:
    try:
        ps = subprocess.run(["ps", "-ax", "-o", "pid=", "-o", "comm="], capture_output=True, text=True, check=True)
        for line in ps.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            pid_str, comm = parts
            last = comm.split("/")[-1]
            if last == name or comm.endswith("/" + name):
                return int(pid_str)
    except Exception:
        pass
    return 0


def frontmost_process_name() -> str:
    try:
        proc = subprocess.run([
            "osascript",
            "-e",
            'tell application "System Events" to get name of first process whose frontmost is true',
        ], capture_output=True, text=True, check=False)
        return proc.stdout.strip()
    except Exception:
        return ""


def get_task(libc, pid: int) -> int:
    self_task = libc.mach_task_self()
    task = ctypes.c_uint32(0)
    kr = libc.task_for_pid(self_task, pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"task_for_pid 失败（kr={kr}）。请使用 sudo 或检查签名/entitlements/SIP/TCC 限制。")
    return task.value


def read_memory(libc, task: int, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    out_size = ctypes.c_uint64(0)
    kr = libc.mach_vm_read_overwrite(task, ctypes.c_uint64(address), ctypes.c_uint64(size), ctypes.c_uint64(ctypes.addressof(buf)), ctypes.byref(out_size))
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"mach_vm_read_overwrite 失败（kr={kr}）@0x{address:x}")
    return ctypes.string_at(ctypes.addressof(buf), out_size.value)


def ensure_writable(libc, task: int, address: int, size: int) -> None:
    kr = libc.mach_vm_protect(task, ctypes.c_uint64(address), ctypes.c_uint64(size), True, VM_PROT_READ | VM_PROT_WRITE)
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"mach_vm_protect 失败（kr={kr}）@0x{address:x}")


def write_memory(libc, task: int, address: int, data: bytes) -> None:
    buf = ctypes.create_string_buffer(data)
    kr = libc.mach_vm_write(task, ctypes.c_uint64(address), ctypes.c_uint64(ctypes.addressof(buf)), ctypes.c_uint32(len(data)))
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"mach_vm_write 失败（kr={kr}）@0x{address:x}")


def scan_regions_for_pattern(libc, task: int, pattern: bytes, limit_mb: int = 128, max_results: int = 2048, require_writable: bool = False) -> list:
    results = []
    scanned_bytes = 0
    limit_bytes = int(limit_mb) * 1024 * 1024
    address = ctypes.c_uint64(1)
    size = ctypes.c_uint64(0)
    flavor = ctypes.c_uint32(VM_REGION_BASIC_INFO_64)
    info = vm_region_basic_info_64()
    info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = ctypes.c_uint32(0)
    while True:
        kr = libc.mach_vm_region(ctypes.c_uint32(task), ctypes.byref(address), ctypes.byref(size), flavor, ctypes.byref(info), ctypes.byref(info_count), ctypes.byref(object_name))
        if kr != KERN_SUCCESS:
            break
        base = address.value
        rsize = size.value
        prot = info.data[0]
        readable = bool(prot & VM_PROT_READ)
        writable = bool(prot & VM_PROT_WRITE)
        if readable and (writable or not require_writable):
            chunk = 256 * 1024
            off = 0
            while off < rsize:
                if scanned_bytes >= limit_bytes or len(results) >= max_results:
                    break
                to_read = min(chunk, rsize - off)
                try:
                    buf = read_memory(libc, task, int(base + off), int(to_read))
                except Exception:
                    buf = b""
                if buf:
                    idx = 0
                    while True:
                        i = buf.find(pattern, idx)
                        if i == -1:
                            break
                        results.append(int(base + off + i))
                        if len(results) >= max_results:
                            break
                        idx = i + 1
                    scanned_bytes += len(buf)
                off += to_read
        address = ctypes.c_uint64(base + rsize)
        if scanned_bytes >= limit_bytes or len(results) >= max_results:
            break
    return results


def read_vector3(libc, task: int, address: int) -> tuple:
    buf = read_memory(libc, task, address, 12)
    x = struct.unpack('<f', buf[0:4])[0]
    y = struct.unpack('<f', buf[4:8])[0]
    z = struct.unpack('<f', buf[8:12])[0]
    return (x, y, z)


def write_vector3(libc, task: int, address: int, vec: tuple) -> None:
    x, y, z = vec
    buf = struct.pack('<fff', float(x), float(y), float(z))
    ensure_writable(libc, task, address, 12)
    write_memory(libc, task, address, buf)


def save_json(path: str, payload: dict) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_json(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="macOS 进程内地址发现：按唯一坐标或整数值扫描候选地址，并可验证/试写")
    ap.add_argument("--pid", type=int, help="目标进程 PID")
    ap.add_argument("--name", type=str, help="目标进程名（精确匹配二进制名）")
    ap.add_argument("--auto", action="store_true", help="自动选择前台进程（无法确定 PID/进程名时）")
    ap.add_argument("--mode", type=str, choices=["search-xyz", "verify-xyz", "write-xyz", "search-int", "intersect"], required=True)
    ap.add_argument("--x", type=float, help="唯一探针坐标 X（float）")
    ap.add_argument("--y", type=float, help="唯一探针坐标 Y（float）")
    ap.add_argument("--z", type=float, help="唯一探针坐标 Z（float）")
    ap.add_argument("--int", dest="ival", type=int, help="唯一整数值（例如唯一 block_id）")
    ap.add_argument("--limit-mb", type=int, default=128, help="扫描读取上限（MB）")
    ap.add_argument("--max-results", type=int, default=2048, help="最多候选地址数量")
    ap.add_argument("--epsilon", type=float, default=1e-5, help="浮点比对容差")
    ap.add_argument("--require-writable", action="store_true", help="仅扫描可写区域（适用于写测试前的筛选）")
    ap.add_argument("--dry-run", action="store_true", help="写测试仅打印而不实际写入")
    ap.add_argument("--output", type=str, help="输出 JSON 文件路径")
    ap.add_argument("--inputs", nargs="+", help="用于 intersect 的输入 JSON 文件列表")
    args = ap.parse_args()

    pid = args.pid or 0
    if not pid and args.name:
        pid = find_pid_by_name(args.name)
    if not pid and args.auto:
        n = frontmost_process_name()
        if n:
            pid = find_pid_by_name(n)
    if not pid and args.mode != "intersect":
        print("[ERR] 需要 --pid / --name / --auto 指定目标进程", file=sys.stderr)
        sys.exit(1)

    libc = load_libc()
    setup_prototypes(libc)

    if args.mode == "intersect":
        if not args.inputs:
            print("[ERR] intersect 需要 --inputs JSON 文件列表", file=sys.stderr)
            sys.exit(2)
        sets = []
        for p in args.inputs:
            try:
                data = load_json(p)
                addrs = set(int(a) for a in data.get("addresses", []))
                sets.append(addrs)
            except Exception as e:
                print(f"[WARN] 读取 {p} 失败：{e}")
        inter = list(set.intersection(*sets)) if sets else []
        payload = {"mode": "intersect", "inputs": args.inputs, "addresses": inter}
        if args.output:
            save_json(args.output, payload)
        print(f"[*] 交集候选数量：{len(inter)}")
        sys.exit(0)

    task = get_task(libc, pid)

    if args.mode == "search-xyz":
        if args.x is None or args.y is None or args.z is None:
            print("[ERR] search-xyz 需要 --x --y --z", file=sys.stderr)
            sys.exit(2)
        pat = struct.pack('<fff', float(args.x), float(args.y), float(args.z))
        addrs = scan_regions_for_pattern(libc, task, pat, limit_mb=args.limit_mb, max_results=args.max_results, require_writable=args.require_writable)
        payload = {"mode": "search-xyz", "pid": pid, "xyz": [args.x, args.y, args.z], "addresses": addrs}
        if args.output:
            save_json(args.output, payload)
        print(f"[*] 候选地址数量：{len(addrs)}")
        for a in addrs[:50]:
            print(f"  0x{a:x}")
        sys.exit(0)

    if args.mode == "search-int":
        if args.ival is None:
            print("[ERR] search-int 需要 --int", file=sys.stderr)
            sys.exit(2)
        pat = int(args.ival).to_bytes(4, 'little', signed=False)
        addrs = scan_regions_for_pattern(libc, task, pat, limit_mb=args.limit_mb, max_results=args.max_results, require_writable=args.require_writable)
        payload = {"mode": "search-int", "pid": pid, "int": args.ival, "addresses": addrs}
        if args.output:
            save_json(args.output, payload)
        print(f"[*] 候选地址数量：{len(addrs)}")
        for a in addrs[:50]:
            print(f"  0x{a:x}")
        sys.exit(0)

    if args.mode == "verify-xyz":
        if args.output:
            print("[WARN] verify-xyz 不写输出，仅打印校验结果")
        if args.x is None or args.y is None or args.z is None or not args.inputs:
            print("[ERR] verify-xyz 需要 --x --y --z 与 --inputs（候选地址 JSON）", file=sys.stderr)
            sys.exit(2)
        eps = float(args.epsilon)
        total = 0
        matched = 0
        for p in args.inputs:
            data = load_json(p)
            addrs = data.get("addresses", [])
            for a in addrs:
                total += 1
                try:
                    vx, vy, vz = read_vector3(libc, task, int(a))
                    ok = (abs(vx - args.x) <= eps) and (abs(vy - args.y) <= eps) and (abs(vz - args.z) <= eps)
                    if ok:
                        matched += 1
                        print(f"[OK] 0x{int(a):x} 匹配 ({vx:.6f},{vy:.6f},{vz:.6f})")
                except Exception:
                    pass
        print(f"[*] 校验完成：{matched}/{total} 匹配")
        sys.exit(0)

    if args.mode == "write-xyz":
        if args.x is None or args.y is None or args.z is None or not args.inputs:
            print("[ERR] write-xyz 需要 --x --y --z 与 --inputs（候选地址 JSON）", file=sys.stderr)
            sys.exit(2)
        vec = (args.x, args.y, args.z)
        for p in args.inputs:
            data = load_json(p)
            addrs = data.get("addresses", [])
            for a in addrs:
                a = int(a)
                if args.dry_run:
                    print(f"[DRY] 将写入 0x{a:x} 为 {vec}")
                else:
                    try:
                        write_vector3(libc, task, a, vec)
                        time.sleep(0.02)
                        vx, vy, vz = read_vector3(libc, task, a)
                        print(f"[OK] 写入并回读 0x{a:x} => ({vx:.6f},{vy:.6f},{vz:.6f})")
                    except Exception as e:
                        print(f"[ERR] 写入失败 0x{a:x}：{e}")
        sys.exit(0)


if __name__ == "__main__":
    main()

