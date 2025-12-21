#!/usr/bin/env python3
"""
macOS 只读内存探测 PoC：
- 使用 Mach API（task_for_pid / mach_vm_region / mach_vm_read_overwrite）只读扫描进程内存
- 启发式查找 16 字节结构 [x(4), y(4), z(4), type(4)]（小端）
- 将解析到的 {(x,y,z): type} 与 blueprint.json 对比并输出差异

重要说明：
- 需要足够的权限（通常为 root），且可能受 SIP/TCC/签名/entitlements 限制。
- 不进行任何写入或代码注入，严格只读；仍可能因保护页或权限不足而失败。
"""

import argparse
import ctypes
import ctypes.util
import subprocess
import json
import sys
from typing import Dict, Tuple, List


# Mach / VM 常量
KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 10  # natural_t 计数，常见为 10

VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4


class vm_region_basic_info_64(ctypes.Structure):
    # 使用 10 个 natural_t 字段以匹配 COUNT，避免详细结构映射复杂性
    _fields_ = [("data", ctypes.c_uint32 * VM_REGION_BASIC_INFO_COUNT_64)]


def load_libc():
    path = ctypes.util.find_library("c")
    if not path:
        raise RuntimeError("无法找到 libc（libSystem）库")
    return ctypes.CDLL(path, use_errno=True)


def setup_prototypes(libc):
    # mach_task_self
    libc.mach_task_self.restype = ctypes.c_uint32  # mach_port_t
    libc.mach_task_self.argtypes = []

    # task_for_pid
    libc.task_for_pid.restype = ctypes.c_int  # kern_return_t
    libc.task_for_pid.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]

    # mach_vm_region
    libc.mach_vm_region.restype = ctypes.c_int  # kern_return_t
    libc.mach_vm_region.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.POINTER(ctypes.c_uint64),  # address in/out
        ctypes.POINTER(ctypes.c_uint64),  # size out
        ctypes.c_uint32,  # flavor
        ctypes.c_void_p,  # info out (vm_region_info_t)
        ctypes.POINTER(ctypes.c_uint32),  # count in/out
        ctypes.POINTER(ctypes.c_uint32),  # object_name out
    ]

    # mach_vm_read_overwrite
    libc.mach_vm_read_overwrite.restype = ctypes.c_int
    libc.mach_vm_read_overwrite.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.c_uint64,  # address
        ctypes.c_uint64,  # size
        ctypes.c_uint64,  # data (用户空间缓冲区地址)
        ctypes.POINTER(ctypes.c_uint64),  # out_size
    ]


def find_pid_by_name(name: str) -> int:
    """通过 pgrep 或 ps 查找进程 PID（返回第一个匹配）。"""
    # 优先 pgrep 精确匹配
    try:
        proc = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True, check=False)
        lines = proc.stdout.strip().split()
        if lines:
            return int(lines[0])
    except Exception:
        pass

    # 退化到 ps 解析
    try:
        proc = subprocess.run(["ps", "-ax", "-o", "pid=", "-o", "comm="], capture_output=True, text=True, check=True)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            pid_str, comm = parts
            # 比较最后路径段是否匹配
            last = comm.split("/")[-1]
            if last == name:
                return int(pid_str)
    except Exception:
        pass
    return -1


def scan_buffer_for_blocks(buf: bytes, coord_min=-4096, coord_max=4096, type_min=0, type_max=4096) -> List[Tuple[int, int, int, int]]:
    """在缓冲区内扫描可能的 [x,y,z,type] 结构（小端 4 字节对齐）。"""
    found = []
    sz = len(buf)
    i = 0
    while i + 16 <= sz:
        x = int.from_bytes(buf[i : i + 4], "little", signed=True)
        y = int.from_bytes(buf[i + 4 : i + 8], "little", signed=True)
        z = int.from_bytes(buf[i + 8 : i + 12], "little", signed=True)
        btype = int.from_bytes(buf[i + 12 : i + 16], "little", signed=False)
        if (coord_min <= x <= coord_max) and (coord_min <= y <= coord_max) and (coord_min <= z <= coord_max) and (
            type_min <= btype <= type_max
        ):
            found.append((x, y, z, btype))
        i += 4  # 以 4 字节步进（既覆盖对齐也覆盖可能的滑动）
    return found


def scan_process_memory(pid: int, limit_mb: int = 256, coord_min=-4096, coord_max=4096, type_min=0, type_max=4096) -> Dict[Tuple[int, int, int], int]:
    """枚举并扫描进程内存，只读提取可能的方块记录，返回 {(x,y,z): type}。"""
    libc = load_libc()
    setup_prototypes(libc)

    self_task = libc.mach_task_self()
    task = ctypes.c_uint32(0)
    kr = libc.task_for_pid(self_task, pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise RuntimeError(
            f"task_for_pid 失败（kr={kr}）。需要 root、适当的签名/entitlements，或禁用相关限制。"
        )

    results: Dict[Tuple[int, int, int], int] = {}
    scanned_bytes = 0
    limit_bytes = limit_mb * 1024 * 1024

    address = ctypes.c_uint64(1)  # 从 1 开始遍历区域
    size = ctypes.c_uint64(0)
    flavor = ctypes.c_uint32(VM_REGION_BASIC_INFO_64)
    info = vm_region_basic_info_64()
    info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = ctypes.c_uint32(0)

    while True:
        # 查询当前 address 所在区域
        kr = libc.mach_vm_region(
            task.value,
            ctypes.byref(address),
            ctypes.byref(size),
            flavor.value,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name),
        )
        if kr != KERN_SUCCESS:
            break

        region_base = address.value
        region_size = size.value

        # 可读性检查（info.data[0] 应为 protection）
        protection = info.data[0]
        readable = bool(protection & VM_PROT_READ)

        # 分块读取，避免单次过大；部分不可读页会报错，忽略即可
        if readable:
            chunk = 256 * 1024
            offset = 0
            while offset < region_size:
                if scanned_bytes >= limit_bytes:
                    break
                to_read = min(chunk, region_size - offset)
                buf = ctypes.create_string_buffer(to_read)
                out_size = ctypes.c_uint64(0)
                kr2 = libc.mach_vm_read_overwrite(
                    task.value,
                    ctypes.c_uint64(region_base + offset),
                    ctypes.c_uint64(to_read),
                    ctypes.c_uint64(ctypes.addressof(buf)),
                    ctypes.byref(out_size),
                )
                if kr2 == KERN_SUCCESS and out_size.value:
                    data = ctypes.string_at(ctypes.addressof(buf), out_size.value)
                    blocks = scan_buffer_for_blocks(data, coord_min=coord_min, coord_max=coord_max, type_min=type_min, type_max=type_max)
                    for x, y, z, btype in blocks:
                        results[(x, y, z)] = btype
                    scanned_bytes += out_size.value
                offset += to_read

        # 跳到下一区域
        address = ctypes.c_uint64(region_base + region_size)
        if scanned_bytes >= limit_bytes:
            break

    return results


def load_blueprint(path: str) -> Dict[Tuple[int, int, int], int]:
    """加载蓝图 JSON（兼容你当前脚本的结构）。返回 {(x,y,z): type}。"""
    with open(path, "r", encoding="utf-8") as f:
        bp = json.load(f)
    out: Dict[Tuple[int, int, int], int] = {}
    for block in bp:
        # 兼容结构：block[2] = [x,y,z]；block[3][0] = type；block[4] = action
        try:
            x, y, z = block[2]
            btype = block[3][0]
            out[(int(x), int(y), int(z))] = int(btype)
        except Exception:
            continue
    return out


def compare_states(game_state: Dict[Tuple[int, int, int], int], blueprint: Dict[Tuple[int, int, int], int]) -> Dict[str, List[Tuple[int, int, int, int]]]:
    missing = []
    mismatch = []
    for pos, btype in blueprint.items():
        gt = game_state.get(pos)
        if gt is None:
            missing.append((*pos, btype))
        elif gt != btype:
            mismatch.append((*pos, btype))
    return {"missing": missing, "mismatch": mismatch}


def main():
    ap = argparse.ArgumentParser(description="macOS 只读内存探测（PoC）")
    ap.add_argument("--pid", type=int, help="目标进程 PID")
    ap.add_argument("--name", type=str, help="目标进程名（如 Game.app 的二进制名）")
    ap.add_argument("--blueprint", type=str, default="blueprint.json", help="蓝图 JSON 路径")
    ap.add_argument("--limit-mb", type=int, default=256, help="扫描上限（MB），避免长时间占用")
    ap.add_argument("--coord-min", type=int, default=-4096, help="坐标最小值过滤")
    ap.add_argument("--coord-max", type=int, default=4096, help="坐标最大值过滤")
    ap.add_argument("--type-min", type=int, default=0, help="类型最小值过滤")
    ap.add_argument("--type-max", type=int, default=4096, help="类型最大值过滤")
    ap.add_argument("--output", type=str, default="probe_result.json", help="输出结果 JSON 路径")
    args = ap.parse_args()

    pid = args.pid or 0
    if not pid and args.name:
        pid = find_pid_by_name(args.name)
    if not pid:
        print("[ERR] 未提供 --pid 或无法通过 --name 找到进程。", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 只读扫描进程 PID={pid}，上限 {args.limit_mb} MB")
    try:
        game_state = scan_process_memory(
            pid,
            limit_mb=args.limit_mb,
            coord_min=args.coord_min,
            coord_max=args.coord_max,
            type_min=args.type_min,
            type_max=args.type_max,
        )
    except Exception as e:
        print(f"[ERR] 扫描失败：{e}", file=sys.stderr)
        sys.exit(2)
    print(f"[OK] 扫描完成，候选方块条目：{len(game_state)}")

    try:
        blueprint = load_blueprint(args.blueprint)
    except Exception as e:
        print(f"[ERR] 蓝图读取失败：{e}", file=sys.stderr)
        sys.exit(3)

    diff = compare_states(game_state, blueprint)
    out = {
        "summary": {
            "game_entries": len(game_state),
            "blueprint_entries": len(blueprint),
            "missing": len(diff["missing"]),
            "mismatch": len(diff["mismatch"]),
        },
        "missing": diff["missing"][:500],  # 仅输出前 500 以防文件过大
        "mismatch": diff["mismatch"][:500],
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[OK] 结果已写入 {args.output}")


if __name__ == "__main__":
    main()

