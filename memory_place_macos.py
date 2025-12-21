#!/usr/bin/env python3
"""
macOS 内存读取 + 自动放置：
- 读取：使用 Mach API（task_for_pid / mach_vm_read_overwrite）按配置读取游戏内存中的方块状态区域
- 对比：与蓝图（JSON）进行比对，计算缺失或不匹配的方块
- 放置：始终使用 Mach API（mach_vm_write / 可选 mach_vm_protect）向配置的放置缓冲写入指令并触发

注意事项：
- 需要足够权限（通常 root），并可能受 SIP/TCC/签名/entitlements 限制
- 实际地址、偏移、触发机制需由你通过调试器/逆向确认并填写到配置
"""

import argparse
import ctypes
import ctypes.util
import json
import math
import struct
import subprocess
import sys
import time
from typing import Dict, Tuple, List, Optional, Callable, Any

# 条件导入 matplotlib，用于可视化
_has_matplotlib = False
plt = None
np = None

# 尝试导入 matplotlib 和 numpy
try:
    import matplotlib.pyplot as plt
    import numpy as np
    _has_matplotlib = True
    from matplotlib.animation import FuncAnimation
    from matplotlib.colors import ListedColormap
    from mpl_toolkits.mplot3d import Axes3D
except ImportError:
    print("[WARN] 无法导入 matplotlib，可视化功能将不可用")


# Mach / VM 常量
KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 10

VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

# 日志级别定义
LOG_LEVELS = {
    'DEBUG': 0,
    'INFO': 1,
    'WARN': 2,
    'ERROR': 3,
    'CRITICAL': 4
}

# 默认日志级别
DEFAULT_LOG_LEVEL = 'INFO'

# 当前日志级别
_current_log_level = LOG_LEVELS[DEFAULT_LOG_LEVEL]

# 日志文件路径
_log_file = None


def set_log_level(level: str) -> None:
    """设置日志级别
    
    Args:
        level: 日志级别（DEBUG, INFO, WARN, ERROR, CRITICAL）
    """
    global _current_log_level
    _current_log_level = LOG_LEVELS.get(level.upper(), LOG_LEVELS[DEFAULT_LOG_LEVEL])


def set_log_file(file_path: str) -> None:
    """设置日志文件
    
    Args:
        file_path: 日志文件路径
    """
    global _log_file
    _log_file = file_path


def log(level: str, message: str, *args, **kwargs) -> None:
    """记录日志
    
    Args:
        level: 日志级别（DEBUG, INFO, WARN, ERROR, CRITICAL）
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    level_upper = level.upper()
    level_num = LOG_LEVELS.get(level_upper, LOG_LEVELS[DEFAULT_LOG_LEVEL])
    
    if level_num < _current_log_level:
        return
    
    # 格式化日志消息
    if args or kwargs:
        message = message.format(*args, **kwargs)
    
    # 构建日志行
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_line = f"[{timestamp}] [{level_upper}] {message}"
    
    # 输出到控制台
    print(log_line)
    
    # 输出到文件
    if _log_file:
        try:
            with open(_log_file, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')
        except Exception as e:
            warn(f"无法写入日志文件: {e}")


def debug(message: str, *args, **kwargs) -> None:
    """记录DEBUG级别日志
    
    Args:
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    log('DEBUG', message, *args, **kwargs)


def info(message: str, *args, **kwargs) -> None:
    """记录INFO级别日志
    
    Args:
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    log('INFO', message, *args, **kwargs)


def warn(message: str, *args, **kwargs) -> None:
    """记录WARN级别日志
    
    Args:
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    log('WARN', message, *args, **kwargs)


def error(message: str, *args, **kwargs) -> None:
    """记录ERROR级别日志
    
    Args:
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    log('ERROR', message, *args, **kwargs)


def critical(message: str, *args, **kwargs) -> None:
    """记录CRITICAL级别日志
    
    Args:
        message: 日志消息
        *args: 格式化参数
        **kwargs: 额外参数
    """
    log('CRITICAL', message, *args, **kwargs)


# ===== 可视化功能 =====
class VisualizationManager:
    """可视化管理器，用于实时显示移动路径和状态"""
    
    def __init__(self):
        self.fig = None
        self.ax = None
        self.animation = None
        self.game_state = None
        self.path = None
        self.player_pos = None
        self.blueprint = None
        self.is_3d = False
        self.running = False
    
    def is_available(self) -> bool:
        """检查可视化功能是否可用
        
        Returns:
            bool: 可视化功能可用返回 True
        """
        return _has_matplotlib
    
    def initialize(self, game_state: Dict[Tuple[int, int, int], int], blueprint: Dict[Tuple[int, int, int], int], is_3d: bool = False) -> bool:
        """初始化可视化环境
        
        Args:
            game_state: 游戏状态字典，{(x,y,z): block_type}
            blueprint: 蓝图字典，{(x,y,z): block_type}
            is_3d: 是否使用3D可视化
        
        Returns:
            bool: 初始化成功返回 True
        """
        if not self.is_available():
            return False
        
        try:
            self.game_state = game_state
            self.blueprint = blueprint
            self.is_3d = is_3d
            
            # 创建图形
            self.fig = plt.figure(figsize=(10, 8))
            
            if is_3d:
                # 创建3D坐标轴
                self.ax = self.fig.add_subplot(111, projection='3d')
                self.ax.set_title('3D 游戏状态与路径可视化')
            else:
                # 创建2D坐标轴
                self.ax = self.fig.add_subplot(111)
                self.ax.set_title('2D 游戏状态与路径可视化')
            
            return True
        except Exception as e:
            print(f"[WARN] 可视化初始化失败: {e}")
            return False
    
    def update_game_state(self, game_state: Dict[Tuple[int, int, int], int]) -> None:
        """更新游戏状态
        
        Args:
            game_state: 新的游戏状态字典
        """
        self.game_state = game_state
    
    def update_path(self, path: List[Tuple[int, int, int]]) -> None:
        """更新路径
        
        Args:
            path: 新的路径列表，[(x,y,z), ...]
        """
        self.path = path
    
    def update_player_pos(self, player_pos: Tuple[float, float, float]) -> None:
        """更新玩家位置
        
        Args:
            player_pos: 玩家当前位置 (x, y, z)
        """
        self.player_pos = player_pos
    
    def draw_2d(self) -> None:
        """绘制2D可视化
        
        绘制内容：
        - 游戏中的方块（灰色）
        - 蓝图中的方块（蓝色）
        - 规划的路径（红色）
        - 玩家当前位置（绿色）
        """
        if not self.ax or not self.game_state:
            return
        
        self.ax.clear()
        self.ax.set_title('2D 游戏状态与路径可视化')
        self.ax.set_xlabel('X 坐标')
        self.ax.set_ylabel('Z 坐标')
        
        # 设置轴范围
        all_positions = list(self.game_state.keys()) + list(self.blueprint.keys())
        if all_positions:
            min_x = min(pos[0] for pos in all_positions) - 5
            max_x = max(pos[0] for pos in all_positions) + 5
            min_z = min(pos[2] for pos in all_positions) - 5
            max_z = max(pos[2] for pos in all_positions) + 5
            self.ax.set_xlim(min_x, max_x)
            self.ax.set_ylim(min_z, max_z)
        
        # 绘制游戏中的方块（灰色）
        game_x = [pos[0] for pos in self.game_state.keys()]
        game_z = [pos[2] for pos in self.game_state.keys()]
        self.ax.scatter(game_x, game_z, c='gray', s=50, label='游戏方块', alpha=0.5)
        
        # 绘制蓝图中的方块（蓝色）
        blueprint_x = [pos[0] for pos in self.blueprint.keys()]
        blueprint_z = [pos[2] for pos in self.blueprint.keys()]
        self.ax.scatter(blueprint_x, blueprint_z, c='blue', s=50, label='蓝图方块', alpha=0.5)
        
        # 绘制路径（红色）
        if self.path:
            path_x = [pos[0] for pos in self.path]
            path_z = [pos[2] for pos in self.path]
            self.ax.plot(path_x, path_z, c='red', linewidth=2, label='规划路径')
            # 路径点
            self.ax.scatter(path_x, path_z, c='red', s=20, alpha=0.8)
        
        # 绘制玩家位置（绿色）
        if self.player_pos:
            self.ax.scatter(self.player_pos[0], self.player_pos[2], c='green', s=100, label='玩家位置', marker='*')
        
        self.ax.legend()
        self.ax.grid(True, linestyle='--', alpha=0.7)
    
    def draw_3d(self) -> None:
        """绘制3D可视化
        
        绘制内容：
        - 游戏中的方块（灰色）
        - 蓝图中的方块（蓝色）
        - 规划的路径（红色）
        - 玩家当前位置（绿色）
        """
        if not self.ax or not self.game_state:
            return
        
        self.ax.clear()
        self.ax.set_title('3D 游戏状态与路径可视化')
        self.ax.set_xlabel('X 坐标')
        self.ax.set_ylabel('Y 坐标')
        self.ax.set_zlabel('Z 坐标')
        
        # 设置轴范围
        all_positions = list(self.game_state.keys()) + list(self.blueprint.keys())
        if all_positions:
            min_x = min(pos[0] for pos in all_positions) - 5
            max_x = max(pos[0] for pos in all_positions) + 5
            min_y = min(pos[1] for pos in all_positions) - 5
            max_y = max(pos[1] for pos in all_positions) + 5
            min_z = min(pos[2] for pos in all_positions) - 5
            max_z = max(pos[2] for pos in all_positions) + 5
            self.ax.set_xlim(min_x, max_x)
            self.ax.set_ylim(min_y, max_y)
            self.ax.set_zlim(min_z, max_z)
        
        # 绘制游戏中的方块（灰色）
        game_x = [pos[0] for pos in self.game_state.keys()]
        game_y = [pos[1] for pos in self.game_state.keys()]
        game_z = [pos[2] for pos in self.game_state.keys()]
        self.ax.scatter(game_x, game_y, game_z, c='gray', s=20, label='游戏方块', alpha=0.5)
        
        # 绘制蓝图中的方块（蓝色）
        blueprint_x = [pos[0] for pos in self.blueprint.keys()]
        blueprint_y = [pos[1] for pos in self.blueprint.keys()]
        blueprint_z = [pos[2] for pos in self.blueprint.keys()]
        self.ax.scatter(blueprint_x, blueprint_y, blueprint_z, c='blue', s=20, label='蓝图方块', alpha=0.5)
        
        # 绘制路径（红色）
        if self.path:
            path_x = [pos[0] for pos in self.path]
            path_y = [pos[1] for pos in self.path]
            path_z = [pos[2] for pos in self.path]
            self.ax.plot(path_x, path_y, path_z, c='red', linewidth=2, label='规划路径')
            # 路径点
            self.ax.scatter(path_x, path_y, path_z, c='red', s=15, alpha=0.8)
        
        # 绘制玩家位置（绿色）
        if self.player_pos:
            self.ax.scatter(self.player_pos[0], self.player_pos[1], self.player_pos[2], c='green', s=50, label='玩家位置', marker='*')
        
        self.ax.legend()
        self.ax.grid(True, linestyle='--', alpha=0.5)
    
    def draw(self) -> None:
        """绘制可视化内容"""
        if not self.is_available() or not self.fig:
            return
        
        if self.is_3d:
            self.draw_3d()
        else:
            self.draw_2d()
        
        # 更新图形
        plt.draw()
        plt.pause(0.01)  # 短暂暂停以更新图形
    
    def show(self, block: bool = True) -> None:
        """显示可视化窗口
        
        Args:
            block: 是否阻塞主线程
        """
        if not self.is_available() or not self.fig:
            return
        
        try:
            self.draw()
            if block:
                plt.show()
            else:
                plt.ion()
                plt.show(block=False)
        except Exception as e:
            print(f"[WARN] 可视化显示失败: {e}")
    
    def close(self) -> None:
        """关闭可视化窗口"""
        if not self.is_available():
            return
        
        try:
            plt.close(self.fig)
            self.fig = None
            self.ax = None
        except Exception as e:
            print(f"[WARN] 可视化关闭失败: {e}")


# 全局可视化管理器实例
visualization_manager = VisualizationManager()


# 输入模拟常量（CGEvent API）
KEYBOARD_EVENT = 1
MOUSE_EVENT = 2

# CGEvent 键码映射
KEY_CODES = {
    'w': 0x0D,
    'a': 0x00,
    's': 0x01,
    'd': 0x02,
    'space': 0x31,
    'shift': 0x38,
    'control': 0x3B,
    'option': 0x3A,
    'command': 0x37,
}

# CGEvent 常量
CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE = 0
kCGEventKeyDown = 10
kCGEventKeyUp = 11
kCGEventMouseMoved = 5
kCGEventLeftMouseDown = 1
kCGEventLeftMouseUp = 2
kCGEventLeftMouseDragged = 3


class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [("data", ctypes.c_uint32 * VM_REGION_BASIC_INFO_COUNT_64)]


def load_libc():
    path = ctypes.util.find_library("c")
    if not path:
        raise RuntimeError("无法找到 libc（libSystem）库")
    return ctypes.CDLL(path, use_errno=True)


def setup_prototypes(libc):
    libc.mach_task_self.restype = ctypes.c_uint32
    libc.mach_task_self.argtypes = []

    libc.task_for_pid.restype = ctypes.c_int
    libc.task_for_pid.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]

    libc.mach_vm_read_overwrite.restype = ctypes.c_int
    libc.mach_vm_read_overwrite.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.c_uint64,  # address
        ctypes.c_uint64,  # size
        ctypes.c_uint64,  # data (用户缓冲区地址)
        ctypes.POINTER(ctypes.c_uint64),
    ]

    libc.mach_vm_write.restype = ctypes.c_int
    libc.mach_vm_write.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.c_uint64,  # address
        ctypes.c_uint64,  # data 指针（vm_offset_t）
        ctypes.c_uint32,  # data_cnt（mach_msg_type_number_t）
    ]

    libc.mach_vm_protect.restype = ctypes.c_int
    libc.mach_vm_protect.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.c_uint64,  # address
        ctypes.c_uint64,  # size
        ctypes.c_bool,    # set_maximum
        ctypes.c_int,     # new_protection
    ]

    # mach_vm_region（用于自动扫描 state）
    libc.mach_vm_region.restype = ctypes.c_int
    libc.mach_vm_region.argtypes = [
        ctypes.c_uint32,  # task
        ctypes.POINTER(ctypes.c_uint64),  # address in/out
        ctypes.POINTER(ctypes.c_uint64),  # size out
        ctypes.c_uint32,  # flavor
        ctypes.c_void_p,  # info out (vm_region_info_t)
        ctypes.POINTER(ctypes.c_uint32),  # count in/out
        ctypes.POINTER(ctypes.c_uint32),  # object_name out
    ]


def load_cgevent():
    """加载 CoreGraphics 库用于 CGEvent API 调用"""
    try:
        # 在 macOS 上加载 CoreGraphics
        cg_path = ctypes.util.find_library("CoreGraphics")
        if not cg_path:
            raise RuntimeError("无法找到 CoreGraphics 库")
        cg = ctypes.CDLL(cg_path)
        
        # 设置 CGEvent API 原型
        cg.CGEventSourceCreate.restype = ctypes.c_void_p
        cg.CGEventSourceCreate.argtypes = [ctypes.c_uint32]
        
        cg.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
        cg.CGEventCreateKeyboardEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_bool]
        
        cg.CGEventCreateMouseEvent.restype = ctypes.c_void_p
        cg.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
        
        cg.CGEventPost.restype = None
        cg.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        
        cg.CGEventSetIntegerValueField.restype = None
        cg.CGEventSetIntegerValueField.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64]
        
        cg.CGEventGetLocation.restype = ctypes.c_void_p
        cg.CGEventGetLocation.argtypes = [ctypes.c_void_p]
        
        cg.CFRelease.restype = None
        cg.CFRelease.argtypes = [ctypes.c_void_p]
        
        return cg
    except Exception as e:
        warn(f"无法加载 CoreGraphics，输入模拟功能将不可用: {e}")
        return None


def simulate_key_press(cg_lib, key_name: str, duration: float = 0.1) -> bool:
    """模拟键盘按键按下和释放
    
    Args:
        cg_lib: CoreGraphics 库实例
        key_name: 按键名称（如 'w', 'a', 's', 'd', 'space'）
        duration: 按键按下持续时间（秒）
    
    Returns:
        bool: 模拟成功返回 True
    """
    if not cg_lib:
        return False
    
    key_code = KEY_CODES.get(key_name.lower())
    if key_code is None:
        warn(f"不支持的按键: {key_name}")
        return False
    
    try:
        # 创建事件源
        event_source = cg_lib.CGEventSourceCreate(CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE)
        if not event_source:
            return False
        
        # 模拟按键按下
        key_down = cg_lib.CGEventCreateKeyboardEvent(event_source, key_code, True)
        if key_down:
            cg_lib.CGEventPost(0x00000001, key_down)  # kCGSessionEventTap
            cg_lib.CFRelease(key_down)
        
        # 等待指定时间
        time.sleep(duration)
        
        # 模拟按键释放
        key_up = cg_lib.CGEventCreateKeyboardEvent(event_source, key_code, False)
        if key_up:
            cg_lib.CGEventPost(0x00000001, key_up)  # kCGSessionEventTap
            cg_lib.CFRelease(key_up)
        
        cg_lib.CFRelease(event_source)
        return True
    except Exception as e:
        warn(f"按键模拟失败 {key_name}: {e}")
        return False


def simulate_mouse_move(cg_lib, x: int, y: int) -> bool:
    """模拟鼠标移动到指定坐标
    
    Args:
        cg_lib: CoreGraphics 库实例
        x: 目标 x 坐标
        y: 目标 y 坐标
    
    Returns:
        bool: 模拟成功返回 True
    """
    if not cg_lib:
        return False
    
    try:
        event_source = cg_lib.CGEventSourceCreate(CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE)
        if not event_source:
            return False
        
        # 创建鼠标移动事件
        mouse_event = cg_lib.CGEventCreateMouseEvent(event_source, kCGEventMouseMoved, 
                                                   ctypes.c_void_p(x + y * (1 << 32)), 0)
        if mouse_event:
            cg_lib.CGEventPost(0x00000001, mouse_event)  # kCGSessionEventTap
            cg_lib.CFRelease(mouse_event)
        
        cg_lib.CFRelease(event_source)
        return True
    except Exception as e:
        warn(f"鼠标移动模拟失败: {e}")
        return False


def simulate_mouse_click(cg_lib, button: int = 0, duration: float = 0.1) -> bool:
    """模拟鼠标点击
    
    Args:
        cg_lib: CoreGraphics 库实例
        button: 鼠标按钮（0: 左键，1: 右键）
        duration: 点击持续时间（秒）
    
    Returns:
        bool: 模拟成功返回 True
    """
    if not cg_lib:
        return False
    
    try:
        event_source = cg_lib.CGEventSourceCreate(CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE)
        if not event_source:
            return False
        
        # 获取当前鼠标位置
        current_event = cg_lib.CGEventCreateKeyboardEvent(event_source, 0, False)
        if not current_event:
            cg_lib.CFRelease(event_source)
            return False
        
        location = cg_lib.CGEventGetLocation(current_event)
        cg_lib.CFRelease(current_event)
        
        # 模拟鼠标按下
        mouse_down = cg_lib.CGEventCreateMouseEvent(event_source, kCGEventLeftMouseDown, 
                                                  location, button)
        if mouse_down:
            cg_lib.CGEventPost(0x00000001, mouse_down)  # kCGSessionEventTap
            cg_lib.CFRelease(mouse_down)
        
        # 等待指定时间
        time.sleep(duration)
        
        # 模拟鼠标释放
        mouse_up = cg_lib.CGEventCreateMouseEvent(event_source, kCGEventLeftMouseUp, 
                                                location, button)
        if mouse_up:
            cg_lib.CGEventPost(0x00000001, mouse_up)  # kCGSessionEventTap
            cg_lib.CFRelease(mouse_up)
        
        cg_lib.CFRelease(event_source)
        return True
    except Exception as e:
        warn(f"鼠标点击模拟失败: {e}")
        return False


# ===== 移动模块架构 =====
class MovementModule:
    """移动模块抽象基类，定义统一的移动接口"""
    
    def __init__(self, name: str, game_type: str):
        self.name = name
        self.game_type = game_type
    
    def move_to(self, libc, cg_lib, task: int, config: dict, target: Tuple[float, float, float]) -> bool:
        """移动到目标位置
        
        Args:
            libc: libc 库实例
            cg_lib: CoreGraphics 库实例（用于输入模拟）
            task: 目标进程 task
            config: 配置字典
            target: 目标位置 (x, y, z)
        
        Returns:
            bool: 移动成功返回 True
        """
        raise NotImplementedError("子类必须实现 move_to 方法")
    
    def aim_at(self, libc, cg_lib, task: int, config: dict, player_pos: Optional[Tuple[float, float, float]], target: Tuple[float, float, float]) -> bool:
        """瞄准目标位置
        
        Args:
            libc: libc 库实例
            cg_lib: CoreGraphics 库实例（用于输入模拟）
            task: 目标进程 task
            config: 配置字典
            player_pos: 玩家当前位置，None 则自动获取
            target: 目标位置 (x, y, z)
        
        Returns:
            bool: 瞄准成功返回 True
        """
        raise NotImplementedError("子类必须实现 aim_at 方法")
    
    def read_player_pos(self, libc, task: int, config: dict) -> Optional[Tuple[float, float, float]]:
        """读取玩家当前位置
        
        Args:
            libc: libc 库实例
            task: 目标进程 task
            config: 配置字典
        
        Returns:
            Optional[Tuple[float, float, float]]: 玩家位置，失败返回 None
        """
        raise NotImplementedError("子类必须实现 read_player_pos 方法")


class MinecraftMovementModule(MovementModule):
    """Minecraft 风格的移动模块，针对Minecraft特性优化"""
    
    def __init__(self):
        super().__init__("minecraft", "minecraft")
        # Minecraft 特定配置
        self.walk_speed = 4.317  # Minecraft 默认行走速度
        self.fly_speed = 10.0    # Minecraft 默认飞行速度
        self.jump_power = 0.42   # Minecraft 默认跳跃力度
        self.is_flying = False   # 飞行状态
        self.is_sprinting = False # 冲刺状态
    
    def move_to(self, libc, cg_lib, task: int, config: dict, target: Tuple[float, float, float]) -> bool:
        """Minecraft 风格移动实现
        - 优先使用内存写入（如果配置了）
        - 否则使用A*路径规划 + 键盘模拟
        """
        # 检查是否配置了内存移动
        mconf = config.get("movement", {})
        mv = mconf.get("move_to")
        if mv:
            # 使用内存写入方式移动
            addr = parse_int_auto(mv.get("address"))
            fields = mv.get("fields", {"x": 0, "y": 4, "z": 8})
            dtype = mv.get("dtype", "float")
            override = bool(mv.get("override_protection", False))
            max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
            ensure_writable_if(libc, task, addr, max_off + 4, override)
            write_vector3(libc, task, addr, fields, target, dtype)
            
            # 触发送移动
            trig = mv.get("trigger", {"address": None, "value": 1, "size": 4})
            taddr = trig.get("address")
            if taddr:
                taddr_i = parse_int_auto(taddr)
                tval = int(trig.get("value", 1))
                tsize = int(trig.get("size", 4))
                ensure_writable_if(libc, task, taddr_i, tsize, override)
                write_memory(libc, task, taddr_i, tval.to_bytes(tsize, 'little', signed=False))
            return True
        elif cg_lib:
            # 使用A*路径规划 + 键盘模拟方式移动
            info(f"使用A*路径规划移动到 {target}")
            
            # 获取当前玩家位置
            current_pos = self.read_player_pos(libc, task, config)
            if not current_pos:
                return False
            
            # 将浮点数位置转换为整数坐标（Minecraft 方块坐标）
            start_pos = tuple(map(int, current_pos))
            goal_pos = tuple(map(int, target))
            
            # 获取游戏状态（这里简化处理，实际应该从内存读取）
            # 注意：在实际应用中，应该从内存读取游戏状态以获取准确的方块信息
            game_state = config.get("game_state", {})
            
            # 使用A*算法寻找路径
            path = a_star_search(
                start=start_pos,
                goal=goal_pos,
                game_state=game_state,
                game_type="minecraft",
                allow_diagonal=False,  # Minecraft 通常不允许直接对角线移动
                use_manhattan=True  # 使用曼哈顿距离更适合 Minecraft
            )
            
            if not path:
                warn(f"无法找到从 {start_pos} 到 {goal_pos} 的路径")
                return False
            
            # 执行路径
            info(f"找到路径，共 {len(path)} 个节点: {path}")
            
            # 遍历路径中的每个节点，模拟行走
            for i in range(1, len(path)):
                prev_pos = path[i-1]
                curr_pos = path[i]
                
                # 计算移动方向
                dx = curr_pos[0] - prev_pos[0]
                dz = curr_pos[2] - prev_pos[2]
                
                # 模拟按键
                keys = []
                if dx > 0:
                    keys.append("d")
                elif dx < 0:
                    keys.append("a")
                if dz > 0:
                    keys.append("w")
                elif dz < 0:
                    keys.append("s")
                
                # 模拟按键按下和释放
                for key in keys:
                    simulate_key_press(cg_lib, key, duration=0.1)
                
                # 等待移动完成
                time.sleep(0.2)
                
                # 更新当前位置
                current_pos = self.read_player_pos(libc, task, config)
                if not current_pos:
                    break
                
                # 检查是否到达目标
                dist = math.sqrt(
                    (current_pos[0] - target[0])**2 +
                    (current_pos[1] - target[1])**2 +
                    (current_pos[2] - target[2])**2
                )
                if dist < 1.0:
                    break
            
            return True
        return False
    
    def aim_at(self, libc, cg_lib, task: int, config: dict, player_pos: Optional[Tuple[float, float, float]], target: Tuple[float, float, float]) -> bool:
        """Minecraft 风格瞄准实现"""
        mconf = config.get("movement", {})
        lk = mconf.get("look_at")
        if lk:
            mode = lk.get("mode", "angles")
            override = bool(lk.get("override_protection", False))
            trig = lk.get("trigger", {"address": None, "value": 1, "size": 4})
            
            if mode == "target":
                addr = parse_int_auto(lk.get("address"))
                fields = lk.get("fields", {"x": 0, "y": 4, "z": 8})
                dtype = lk.get("dtype", "float")
                max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
                ensure_writable_if(libc, task, addr, max_off + 4, override)
                write_vector3(libc, task, addr, fields, target, dtype)
            else:
                if not player_pos:
                    player_pos = self.read_player_pos(libc, task, config)
                if not player_pos:
                    return False
                yaw, pitch = compute_yaw_pitch(player_pos, target)
                addr = parse_int_auto(lk.get("address"))
                fields = lk.get("fields", {"yaw": 0, "pitch": 4})
                dtype = lk.get("dtype", "float")
                max_off = max(fields.get("yaw", 0), fields.get("pitch", 4))
                size = max_off + 4
                ensure_writable_if(libc, task, addr, size, override)
                buf = bytearray(size)
                
                def put_angle(off: int, val: float):
                    if dtype == "float":
                        buf[off: off + 4] = struct.pack('<f', float(val))
                    else:
                        buf[off: off + 4] = int(val).to_bytes(4, 'little', signed=True)
                
                put_angle(fields.get("yaw", 0), yaw)
                put_angle(fields.get("pitch", 4), pitch)
                write_memory(libc, task, addr, bytes(buf))
            
            # 触发瞄准
            taddr = trig.get("address")
            if taddr:
                taddr_i = parse_int_auto(taddr)
                tval = int(trig.get("value", 1))
                tsize = int(trig.get("size", 4))
                ensure_writable_if(libc, task, taddr_i, tsize, override)
                write_memory(libc, task, taddr_i, tval.to_bytes(tsize, 'little', signed=False))
            return True
        return False
    
    def read_player_pos(self, libc, task: int, config: dict) -> Optional[Tuple[float, float, float]]:
        """读取 Minecraft 玩家位置"""
        mconf = config.get("movement", {})
        pc = mconf.get("player_pos")
        if not pc:
            return None
        addr = parse_int_auto(pc.get("address"))
        fields = pc.get("fields", {"x": 0, "y": 4, "z": 8})
        dtype = pc.get("dtype", "float")
        return read_vector3(libc, task, addr, fields, dtype)
    
    def jump(self, libc, cg_lib, task: int, config: dict) -> bool:
        """模拟Minecraft跳跃"""
        if cg_lib:
            info("模拟Minecraft跳跃")
            return simulate_key_press(cg_lib, "space", duration=0.1)
        # 或者通过内存写入方式实现
        return False
    
    def sprint(self, libc, cg_lib, task: int, config: dict, enable: bool = True) -> bool:
        """模拟Minecraft冲刺"""
        self.is_sprinting = enable
        if cg_lib:
            info(f"{'启用' if enable else '禁用'}Minecraft冲刺")
            key = "control"  # Minecraft默认冲刺键是Ctrl
            if enable:
                return simulate_key_press(cg_lib, key, duration=0.1)
            # 禁用冲刺不需要额外操作
            return True
        return False
    
    def fly(self, libc, cg_lib, task: int, config: dict, enable: bool = True) -> bool:
        """模拟Minecraft飞行"""
        self.is_flying = enable
        if cg_lib:
            info(f"{'启用' if enable else '禁用'}Minecraft飞行")
            # Minecraft默认飞行键是空格键（在创造模式下）或双击空格键
            if enable:
                # 双击空格键启用飞行
                simulate_key_press(cg_lib, "space", duration=0.1)
                time.sleep(0.1)
                return simulate_key_press(cg_lib, "space", duration=0.1)
            else:
                # 再次按空格键禁用飞行
                return simulate_key_press(cg_lib, "space", duration=0.1)
        return False
    
    def sneak(self, libc, cg_lib, task: int, config: dict, enable: bool = True) -> bool:
        """模拟Minecraft潜行"""
        if cg_lib:
            info(f"{'启用' if enable else '禁用'}Minecraft潜行")
            key = "shift"  # Minecraft默认潜行键是Shift
            return simulate_key_press(cg_lib, key, duration=0.1 if enable else 0.05)
        return False


class GenericMovementModule(MovementModule):
    """通用移动模块，适用于大多数游戏"""
    
    def __init__(self):
        super().__init__("generic", "generic")
    
    def move_to(self, libc, cg_lib, task: int, config: dict, target: Tuple[float, float, float]) -> bool:
        """通用移动实现"""
        # 优先使用配置的移动方式
        if config.get("movement"):
            return MinecraftMovementModule().move_to(libc, cg_lib, task, config, target)
        # 否则使用键盘模拟
        if cg_lib:
            info(f"使用通用键盘模拟移动到 {target}")
            # 这里可以扩展为更通用的键盘模拟
            return True
        return False
    
    def aim_at(self, libc, cg_lib, task: int, config: dict, player_pos: Optional[Tuple[float, float, float]], target: Tuple[float, float, float]) -> bool:
        """通用瞄准实现"""
        if config.get("movement"):
            return MinecraftMovementModule().aim_at(libc, cg_lib, task, config, player_pos, target)
        return False
    
    def read_player_pos(self, libc, task: int, config: dict) -> Optional[Tuple[float, float, float]]:
        """读取通用游戏玩家位置"""
        if config.get("movement"):
            return MinecraftMovementModule().read_player_pos(libc, task, config)
        return None


class MovementModuleManager:
    """移动模块管理器，负责加载和切换不同的移动模块"""
    
    def __init__(self):
        self.modules = {
            "minecraft": MinecraftMovementModule(),
            "generic": GenericMovementModule(),
        }
        self.current_module = None
    
    def register_module(self, module: MovementModule) -> None:
        """注册新的移动模块
        
        Args:
            module: 要注册的移动模块实例
        """
        self.modules[module.game_type] = module
    
    def get_module(self, game_type: str) -> Optional[MovementModule]:
        """获取指定游戏类型的移动模块
        
        Args:
            game_type: 游戏类型
        
        Returns:
            Optional[MovementModule]: 移动模块实例，未找到返回 None
        """
        return self.modules.get(game_type) or self.modules.get("generic")
    
    def detect_game_type(self, libc, task: int, config: dict) -> str:
        """自动检测游戏类型
        
        Args:
            libc: libc 库实例
            task: 目标进程 task
            config: 配置字典
        
        Returns:
            str: 检测到的游戏类型
        """
        # 1. 从配置中获取游戏类型
        if config.get("game_type"):
            return config["game_type"]
        
        # 2. 根据进程名检测
        pid = config.get("pid", 0)
        if pid:
            try:
                proc = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, check=False)
                comm = proc.stdout.strip().lower()
                if "minecraft" in comm:
                    return "minecraft"
            except Exception:
                pass
        
        # 3. 根据内存特征检测（简化实现）
        # 这里可以添加更复杂的内存特征检测逻辑
        
        # 默认返回通用类型
        return "generic"
    
    def initialize(self, libc, task: int, config: dict) -> MovementModule:
        """初始化并返回合适的移动模块
        
        Args:
            libc: libc 库实例
            task: 目标进程 task
            config: 配置字典
        
        Returns:
            MovementModule: 初始化的移动模块
        """
        game_type = self.detect_game_type(libc, task, config)
        self.current_module = self.get_module(game_type)
        info(f"使用 {self.current_module.name} 移动模块（游戏类型：{game_type}）")
        return self.current_module


def find_pid_by_name(name: str) -> int:
    try:
        proc = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True, check=False)
        lines = proc.stdout.strip().split()
        if lines:
            return int(lines[0])
    except Exception:
        pass
    try:
        proc = subprocess.run(["ps", "-ax", "-o", "pid=", "-o", "comm="], capture_output=True, text=True, check=True)
        for line in proc.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            pid_str, comm = parts
            if comm.split("/")[-1] == name:
                return int(pid_str)
    except Exception:
        pass
    return -1


def frontmost_process_name() -> Optional[str]:
    """使用 AppleScript 获取当前前台进程名。"""
    try:
        proc = subprocess.run(
            [
                "osascript",
                "-e",
                'tell application "System Events" to get name of first process whose frontmost is true',
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        name = proc.stdout.strip()
        return name or None
    except Exception:
        return None


# ===== 自动扫描 state 区域 =====
def scan_buffer_for_blocks(buf: bytes, coord_min=-4096, coord_max=4096, type_min=0, type_max=4096) -> List[Tuple[int, int, int, int]]:
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
        i += 4
    return found


def auto_scan_state(libc, task: int, limit_mb: int = 128, coord_min=-4096, coord_max=4096, type_min=0, type_max=4096) -> Tuple[Dict[Tuple[int, int, int], int], Dict[Tuple[int, int, int], int]]:
    """枚举进程可读区域并扫描可能的 [x,y,z,type] 结构。
    返回:
    - game_state: {(x,y,z): type}
    - addr_map: {(x,y,z): record_base_address} // 可用于直接写入 type（record_base_address + 12）
    """
    results: Dict[Tuple[int, int, int], int] = {}
    addr_map: Dict[Tuple[int, int, int], int] = {}
    scanned_bytes = 0
    limit_bytes = int(limit_mb) * 1024 * 1024

    address = ctypes.c_uint64(1)
    size = ctypes.c_uint64(0)
    flavor = ctypes.c_uint32(VM_REGION_BASIC_INFO_64)
    info = vm_region_basic_info_64()
    info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = ctypes.c_uint32(0)

    while True:
        kr = libc.mach_vm_region(
            ctypes.c_uint32(task),
            ctypes.byref(address),
            ctypes.byref(size),
            flavor,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name),
        )
        if kr != KERN_SUCCESS:
            break

        region_base = address.value
        region_size = size.value
        protection = info.data[0]
        readable = bool(protection & VM_PROT_READ)

        if readable:
            chunk = 256 * 1024
            offset = 0
            while offset < region_size:
                if scanned_bytes >= limit_bytes:
                    break
                to_read = min(chunk, region_size - offset)
                try:
                    data = read_memory(libc, task, int(region_base + offset), int(to_read))
                except Exception:
                    data = b""
                if data:
                    # 遍历缓冲，捕获记录与起始地址
                    sz = len(data)
                    i = 0
                    while i + 16 <= sz:
                        x = int.from_bytes(data[i : i + 4], "little", signed=True)
                        y = int.from_bytes(data[i + 4 : i + 8], "little", signed=True)
                        z = int.from_bytes(data[i + 8 : i + 12], "little", signed=True)
                        btype = int.from_bytes(data[i + 12 : i + 16], "little", signed=False)
                        if (coord_min <= x <= coord_max) and (coord_min <= y <= coord_max) and (coord_min <= z <= coord_max) and (
                            type_min <= btype <= type_max
                        ):
                            pos = (x, y, z)
                            results[pos] = btype
                            addr_map[pos] = int(region_base + offset + i)
                        i += 4
                    scanned_bytes += len(data)
                offset += to_read

        address = ctypes.c_uint64(region_base + region_size)
        if scanned_bytes >= limit_bytes:
            break

    return results, addr_map


def auto_detect_pid(config: dict) -> int:
    """自动选择目标进程：优先配置名，其次前台进程，最后常见匹配。"""
    # 1) 配置中的显式进程名
    proc_conf = config.get("process", {})
    conf_name = proc_conf.get("name")
    if conf_name:
        pid = find_pid_by_name(conf_name)
        if pid > 0:
            return pid

    # 1.5) 配置中的端口/协议
    conf_port = proc_conf.get("port")
    conf_proto = proc_conf.get("proto")
    if conf_port:
        try:
            pid = find_pid_by_port(int(conf_port), conf_proto)
            if pid > 0:
                return pid
        except Exception:
            pass

    # 2) 前台进程名
    fg_name = frontmost_process_name()
    if fg_name:
        pid = find_pid_by_name(fg_name)
        if pid > 0:
            return pid

    # 3) 通过 patterns 进行模糊匹配
    patterns = proc_conf.get("patterns", [])
    if patterns:
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
                for pat in patterns:
                    if pat in last or pat in comm:
                        return int(pid_str)
        except Exception:
            pass

    return 0


def list_open_ports(pid: int) -> List[str]:
    """列出进程的网络端口（依赖 lsof）。返回如 'TCP *:12345 (LISTEN)' 的行。"""
    try:
        proc = subprocess.run(["lsof", "-nP", "-i", "-a", "-p", str(pid)], capture_output=True, text=True, check=False)
        lines = []
        for line in proc.stdout.splitlines():
            if ":" in line and ("TCP" in line or "UDP" in line):
                lines.append(line.strip())
        return lines
    except Exception:
        return []


def find_pid_by_port(port: int, proto: Optional[str] = None) -> int:
    """通过端口查找进程 PID。proto 可为 'tcp' 或 'udp'。"""
    try:
        proto = (proto or "").lower()
        if proto in ("tcp", "udp"):
            args = ["lsof", "-nP", "-i", f"{proto}:{port}"]
        else:
            args = ["lsof", "-nP", "-i", f":{port}"]
        proc = subprocess.run(args, capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("COMMAND"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    except Exception:
        pass
    return 0


# ===== 移动/视角相关 =====
def read_vector3(libc, task: int, address: int, fields: Dict[str, int], dtype: str = "float") -> Optional[Tuple[float, float, float]]:
    try:
        max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
        size = max_off + 4
        buf = read_memory(libc, task, address, size)
        def parse_at(off: int) -> float:
            b = buf[off: off + 4]
            if dtype == "float":
                return struct.unpack('<f', b)[0]
            return float(int.from_bytes(b, 'little', signed=True))
        x = parse_at(fields.get("x", 0))
        y = parse_at(fields.get("y", 4))
        z = parse_at(fields.get("z", 8))
        return (x, y, z)
    except Exception:
        return None


def write_vector3(libc, task: int, address: int, fields: Dict[str, int], vec: Tuple[float, float, float], dtype: str = "float") -> None:
    x, y, z = vec
    max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
    size = max_off + 4
    buf = bytearray(size)
    def put(off: int, val: float):
        if dtype == "float":
            buf[off: off + 4] = struct.pack('<f', float(val))
        else:
            buf[off: off + 4] = int(val).to_bytes(4, 'little', signed=True)
    put(fields.get("x", 0), x)
    put(fields.get("y", 4), y)
    put(fields.get("z", 8), z)
    write_memory(libc, task, address, bytes(buf))


def ensure_writable_if(libc, task: int, address: int, size: int, override: bool) -> None:
    if override:
        ensure_writable(libc, task, address, size)


def movement_move_to(libc, task: int, config: dict, target: Tuple[float, float, float]) -> bool:
    mconf = config.get("movement", {})
    mv = mconf.get("move_to")
    if not mv:
        return False
    addr = parse_int_auto(mv.get("address"))
    fields = mv.get("fields", {"x": 0, "y": 4, "z": 8})
    dtype = mv.get("dtype", "float")
    override = bool(mv.get("override_protection", False))
    max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
    ensure_writable_if(libc, task, addr, max_off + 4, override)
    write_vector3(libc, task, addr, fields, target, dtype)
    trig = mv.get("trigger", {"address": None, "value": 1, "size": 4})
    taddr = trig.get("address")
    if taddr:
        taddr_i = parse_int_auto(taddr)
        tval = int(trig.get("value", 1))
        tsize = int(trig.get("size", 4))
        ensure_writable_if(libc, task, taddr_i, tsize, override)
        write_memory(libc, task, taddr_i, tval.to_bytes(tsize, 'little', signed=False))
    return True


def movement_read_player_pos(libc, task: int, config: dict) -> Optional[Tuple[float, float, float]]:
    mconf = config.get("movement", {})
    pc = mconf.get("player_pos")
    if not pc:
        return None
    addr = parse_int_auto(pc.get("address"))
    fields = pc.get("fields", {"x": 0, "y": 4, "z": 8})
    dtype = pc.get("dtype", "float")
    return read_vector3(libc, task, addr, fields, dtype)


def scan_float_vector_candidates(libc, task: int, limit_mb: int = 64, range_min: float = -10000.0, range_max: float = 10000.0, max_candidates: int = 256) -> List[int]:
    """扫描可读可写内存，寻找可能的 float 三元组候选地址（返回记录起始地址）。"""
    candidates: List[int] = []
    scanned = 0
    limit = int(limit_mb) * 1024 * 1024
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
        if readable and writable:
            chunk = 256 * 1024
            off = 0
            while off < rsize and scanned < limit and len(candidates) < max_candidates:
                to_read = min(chunk, rsize - off)
                try:
                    buf = read_memory(libc, task, int(base + off), int(to_read))
                except Exception:
                    buf = b""
                if buf:
                    sz = len(buf)
                    i = 0
                    while i + 12 <= sz and len(candidates) < max_candidates:
                        try:
                            x = struct.unpack('<f', buf[i:i+4])[0]
                            y = struct.unpack('<f', buf[i+4:i+8])[0]
                            z = struct.unpack('<f', buf[i+8:i+12])[0]
                        except Exception:
                            i += 4
                            continue
                        if (range_min <= x <= range_max) and (range_min <= y <= range_max) and (range_min <= z <= range_max):
                            candidates.append(int(base + off + i))
                        i += 4
                    scanned += sz
                off += to_read
        address = ctypes.c_uint64(base + rsize)
        if scanned >= limit or len(candidates) >= max_candidates:
            break
    return candidates


def discover_movement(libc, task: int, target_front: Tuple[float, float, float], max_attempts: int = 64) -> Optional[dict]:
    """尝试发现并写入玩家移动位置：对候选 float3 地址逐一试写并回读验证。返回 movement 配置片段。"""
    cands = scan_float_vector_candidates(libc, task, limit_mb=64, max_candidates=max_attempts)
    fields = {"x": 0, "y": 4, "z": 8}
    for addr in cands:
        try:
            # 试写站位
            ensure_writable(libc, task, addr, 12)
            write_vector3(libc, task, addr, fields, target_front, dtype="float")
            time.sleep(0.05)
            # 回读验证（仅验证写入是否生效，不能保证引擎使用）
            vec = read_vector3(libc, task, addr, fields, dtype="float")
            if vec is None:
                continue
            dx = abs(vec[0] - target_front[0])
            dy = abs(vec[1] - target_front[1])
            dz = abs(vec[2] - target_front[2])
            if dx < 0.01 and dy < 0.01 and dz < 0.01:
                return {
                    "player_pos": {"address": f"0x{addr:x}", "fields": fields, "dtype": "float"},
                    "move_to": {"address": f"0x{addr:x}", "fields": fields, "dtype": "float", "trigger": {"address": None, "value": 1, "size": 4}, "override_protection": False},
                }
        except Exception:
            continue
    return None


def movement_wait_arrival(libc, task: int, config: dict, target: Tuple[float, float, float]) -> bool:
    mconf = config.get("movement", {})
    radius = float(mconf.get("arrival_radius", 1.5))
    timeout_ms = int(mconf.get("arrival_timeout_ms", 5000))
    start = time.time()
    while (time.time() - start) * 1000 < timeout_ms:
        pos = movement_read_player_pos(libc, task, config)
        if pos is None:
            time.sleep(0.05)
            continue
        dx = pos[0] - target[0]
        dy = pos[1] - target[1]
        dz = pos[2] - target[2]
        if (dx * dx + dy * dy + dz * dz) ** 0.5 <= radius:
            return True
        time.sleep(0.05)
    return False


def compute_yaw_pitch(from_pos: Tuple[float, float, float], to_pos: Tuple[float, float, float]) -> Tuple[float, float]:
    # 通用计算（可能与具体引擎坐标系有差异，需要根据实际校准）
    dx = to_pos[0] - from_pos[0]
    dy = to_pos[1] - from_pos[1]
    dz = to_pos[2] - from_pos[2]
    yaw = math.degrees(math.atan2(dx, -dz))  # 假设 z 正向为前
    dist = math.sqrt(dx * dx + dz * dz)
    pitch = math.degrees(math.atan2(dy, dist))
    return (yaw, pitch)


def movement_aim_at(libc, task: int, config: dict, player_pos: Optional[Tuple[float, float, float]], target: Tuple[float, float, float]) -> bool:
    mconf = config.get("movement", {})
    lk = mconf.get("look_at")
    if not lk:
        return False
    mode = lk.get("mode", "angles")
    override = bool(lk.get("override_protection", False))
    trig = lk.get("trigger", {"address": None, "value": 1, "size": 4})

    if mode == "target":
        addr = parse_int_auto(lk.get("address"))
        fields = lk.get("fields", {"x": 0, "y": 4, "z": 8})
        dtype = lk.get("dtype", "float")
        max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8))
        ensure_writable_if(libc, task, addr, max_off + 4, override)
        write_vector3(libc, task, addr, fields, target, dtype)
    else:
        if not player_pos:
            player_pos = movement_read_player_pos(libc, task, config)
        if not player_pos:
            return False
        yaw, pitch = compute_yaw_pitch(player_pos, target)
        addr = parse_int_auto(lk.get("address"))
        fields = lk.get("fields", {"yaw": 0, "pitch": 4})
        dtype = lk.get("dtype", "float")
        max_off = max(fields.get("yaw", 0), fields.get("pitch", 4))
        size = max_off + 4
        ensure_writable_if(libc, task, addr, size, override)
        buf = bytearray(size)
        def put_angle(off: int, val: float):
            if dtype == "float":
                buf[off: off + 4] = struct.pack('<f', float(val))
            else:
                buf[off: off + 4] = int(val).to_bytes(4, 'little', signed=True)
        put_angle(fields.get("yaw", 0), yaw)
        put_angle(fields.get("pitch", 4), pitch)
        write_memory(libc, task, addr, bytes(buf))

    taddr = trig.get("address")
    if taddr:
        taddr_i = parse_int_auto(taddr)
        tval = int(trig.get("value", 1))
        tsize = int(trig.get("size", 4))
        ensure_writable_if(libc, task, taddr_i, tsize, override)
        write_memory(libc, task, taddr_i, tval.to_bytes(tsize, 'little', signed=False))
    return True


def parse_int_auto(s: str) -> int:
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        return int(s, 0)  # 支持十六进制如 0x...
    raise ValueError("地址/数值必须为 int 或字符串")


def get_task(libc, pid: int) -> int:
    self_task = libc.mach_task_self()
    task = ctypes.c_uint32(0)
    kr = libc.task_for_pid(self_task, pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"task_for_pid 失败（kr={kr}）。请使用 sudo 或检查签名/entitlements/SIP/TCC 限制。")
    return task.value


def read_memory(libc, task: int, address: int, size: int) -> bytes:
    """读取内存，优化版本：减少内存分配，提高性能
    
    Args:
        libc: libc 库实例
        task: 目标进程 task
        address: 内存地址
        size: 读取大小
    
    Returns:
        bytes: 读取的内存数据
    """
    try:
        # 预分配缓冲区
        buf = ctypes.create_string_buffer(size)
        out_size = ctypes.c_uint64(0)
        
        # 执行内存读取
        kr = libc.mach_vm_read_overwrite(
            task, 
            ctypes.c_uint64(address), 
            ctypes.c_uint64(size), 
            ctypes.c_uint64(ctypes.addressof(buf)), 
            ctypes.byref(out_size)
        )
        
        if kr != KERN_SUCCESS:
            raise RuntimeError(f"mach_vm_read_overwrite 失败（kr={kr}）@0x{address:x}")
        
        # 仅返回实际读取的数据
        return buf.raw[:out_size.value]
    except Exception as e:
        error(f"读取内存失败 @0x{address:x}: {e}")
        raise


def ensure_writable(libc, task: int, address: int, size: int) -> None:
    kr = libc.mach_vm_protect(task, ctypes.c_uint64(address), ctypes.c_uint64(size), True, VM_PROT_READ | VM_PROT_WRITE)
    if kr != KERN_SUCCESS:
        raise RuntimeError(f"mach_vm_protect 失败（kr={kr}）@0x{address:x}")


def write_memory(libc, task: int, address: int, data: bytes) -> None:
    """写入内存，优化版本：减少内存分配，提高性能
    
    Args:
        libc: libc 库实例
        task: 目标进程 task
        address: 内存地址
        data: 要写入的数据
    """
    try:
        if not data:
            return  # 空数据直接返回
        
        # 直接使用数据缓冲区，减少内存分配
        data_len = len(data)
        buf = ctypes.c_char_p(data)
        
        # 执行内存写入
        kr = libc.mach_vm_write(
            task, 
            ctypes.c_uint64(address), 
            ctypes.c_uint64(ctypes.addressof(ctypes.c_char.from_buffer(data))), 
            ctypes.c_uint32(data_len)
        )
        
        if kr != KERN_SUCCESS:
            raise RuntimeError(f"mach_vm_write 失败（kr={kr}）@0x{address:x}")
    except Exception as e:
        error(f"写入内存失败 @0x{address:x}: {e}")
        raise


# ===== Minecraft 方块类型映射 =====
# Minecraft 常用方块类型映射（ID: 名称）
MINECRAFT_BLOCK_TYPES = {
    0: "air",
    1: "stone",
    2: "grass_block",
    3: "dirt",
    4: "cobblestone",
    5: "oak_planks",
    6: "spruce_planks",
    7: "birch_planks",
    8: "jungle_planks",
    9: "acacia_planks",
    10: "dark_oak_planks",
    12: "sand",
    13: "gravel",
    14: "gold_ore",
    15: "iron_ore",
    16: "coal_ore",
    17: "oak_log",
    18: "spruce_log",
    19: "birch_log",
    20: "jungle_log",
    21: "acacia_log",
    22: "dark_oak_log",
    23: "oak_leaves",
    24: "spruce_leaves",
    25: "birch_leaves",
    26: "jungle_leaves",
    27: "acacia_leaves",
    28: "dark_oak_leaves",
    31: "grass",
    32: "fern",
    35: "white_wool",
    40: "glass",
    44: "brick_slab",
    45: "brick_block",
    46: "tnt",
    47: "bookshelf",
    48: "mossy_cobblestone",
    49: "obsidian",
    56: "diamond_ore",
    57: "diamond_block",
    58: "crafting_table",
    60: "farmland",
    61: "furnace",
    62: "lit_furnace",
    63: "oak_stairs",
    64: "oak_door",
    65: "ladder",
    66: "rail",
    67: "cobblestone_stairs",
    68: "wall_torch",
    71: "iron_door",
    73: "redstone_ore",
    74: "lit_redstone_ore",
    78: "snow",
    79: "ice",
    80: "snow_block",
    81: "cactus",
    82: "clay",
    83: "sugar_cane",
    86: "pumpkin",
    89: "glowstone",
    91: "jack_o_lantern",
    98: "stone_brick",
    100: "glass_pane",
    103: "melon",
    104: "pumpkin_stem",
    105: "melon_stem",
    108: "bricks",
    109: "stone_brick_stairs",
    110: "mud_brick_stairs",
    112: "nether_brick",
    113: "nether_brick_fence",
    114: "nether_brick_stairs",
    121: "end_stone",
    122: "end_stone_bricks",
    128: "sandstone_stairs",
    133: "emerald_ore",
    134: "ender_chest",
    139: "emerald_block",
    140: "spruce_stairs",
    141: "birch_stairs",
    142: "jungle_stairs",
    143: "command_block",
    155: "quartz_block",
    156: "quartz_stairs",
    157: "activator_rail",
    163: "acacia_stairs",
    164: "dark_oak_stairs",
    165: "slime_block",
    166: "iron_trapdoor",
    168: "purpur_block",
    169: "purpur_stairs",
    170: "purpur_slab",
    171: "end_rod",
    172: "chorus_plant",
    173: "chorus_flower",
    174: "purpur_pillar",
    181: "end_stone_brick_stairs",
    182: "magenta_glazed_terracotta",
    183: "light_blue_glazed_terracotta",
    184: "yellow_glazed_terracotta",
    185: "brown_glazed_terracotta",
    186: "red_glazed_terracotta",
    187: "orange_glazed_terracotta",
    188: "white_glazed_terracotta",
    189: "light_gray_glazed_terracotta",
    190: "cyan_glazed_terracotta",
    191: "purple_glazed_terracotta",
    192: "blue_glazed_terracotta",
    193: "green_glazed_terracotta",
    194: "lime_glazed_terracotta",
    195: "pink_glazed_terracotta",
    196: "gray_glazed_terracotta",
    200: "black_glazed_terracotta",
    201: "concrete",
    202: "concrete_powder",
    203: "structure_void",
    204: "iron_shulker_box",
    205: "gold_shulker_box",
    206: "diamond_shulker_box",
    207: "emerald_shulker_box",
    208: "black_shulker_box",
    209: "red_shulker_box",
    210: "green_shulker_box",
    211: "brown_shulker_box",
    212: "blue_shulker_box",
    213: "purple_shulker_box",
    214: "cyan_shulker_box",
    215: "light_gray_shulker_box",
    216: "gray_shulker_box",
    217: "pink_shulker_box",
    218: "magenta_shulker_box",
    219: "yellow_shulker_box",
    220: "lime_shulker_box",
    221: "light_blue_shulker_box",
    222: "orange_shulker_box",
    223: "white_shulker_box",
    224: "banner",
    225: "white_bed",
    226: "orange_bed",
    227: "magenta_bed",
    228: "light_blue_bed",
    229: "yellow_bed",
    230: "lime_bed",
    231: "pink_bed",
    232: "gray_bed",
    233: "light_gray_bed",
    234: "cyan_bed",
    235: "purple_bed",
    236: "blue_bed",
    237: "brown_bed",
    238: "green_bed",
    239: "red_bed",
    240: "black_bed",
    241: "structure_block",
    242: "end_gateway",
    243: "repeating_command_block",
    244: "chain_command_block",
    245: "bamboo",
    246: "bamboo_sapling",
    247: "scaffolding",
    250: "barrel",
    251: "smoker",
    252: "blast_furnace",
    253: "lectern",
    254: "bell",
    255: "composter",
    256: "grindstone",
    257: "stonecutter",
    258: "cartography_table",
    259: "fletching_table",
    260: "loom",
    261: "barber_shop",
    262: "lantern",
    263: "campfire",
    264: "soul_campfire",
    265: "lectern",
    266: "beehive",
    267: "bee_nest",
    268: "honey_block",
    269: "honeycomb_block",
    270: "decorated_pot",
    271: "candle",
    272: "sculk_sensor",
    273: "sculk_catalyst",
    274: "sculk",
    275: "sculk_vein",
    276: "sculk_shrieker",
    277: "calibrated_sculk_sensor",
    278: "copper_ore",
    279: "deepslate_copper_ore",
    280: "raw_copper_block",
    281: "exposed_copper",
    282: "weathered_copper",
    283: "oxidized_copper",
    284: "waxed_copper_block",
    285: "waxed_exposed_copper",
    286: "waxed_weathered_copper",
    287: "waxed_oxidized_copper",
    288: "copper_block",
    289: "copper_stairs",
    290: "copper_slab",
    291: "copper_glass",
    292: "copper_trapdoor",
    293: "copper_door",
    294: "lightning_rod",
    295: "amethyst_block",
    296: "budding_amethyst",
    297: "amethyst_cluster",
    298: "small_amethyst_bud",
    299: "medium_amethyst_bud",
    300: "large_amethyst_bud",
    301: "tuff",
    302: "calcite",
    303: "smooth_basalt",
    304: "polished_tuff",
    305: "tuff_bricks",
    306: "tuff_slab",
    307: "tuff_stairs",
    308: "polished_tuff_slab",
    309: "polished_tuff_stairs",
    310: "tuff_wall",
    311: "tuff_brick_wall",
    312: "polished_tuff_wall",
    313: "deepslate",
    314: "polished_deepslate",
    315: "cobbled_deepslate",
    316: "deepslate_bricks",
    317: "deepslate_tiles",
    318: "cobbled_deepslate_wall",
    319: "cobbled_deepslate_slab",
    320: "cobbled_deepslate_stairs",
    321: "polished_deepslate_wall",
    322: "polished_deepslate_slab",
    323: "polished_deepslate_stairs",
    324: "deepslate_brick_wall",
    325: "deepslate_brick_slab",
    326: "deepslate_brick_stairs",
    327: "deepslate_tile_wall",
    328: "deepslate_tile_slab",
    329: "deepslate_tile_stairs",
    330: "deepslate_coal_ore",
    331: "deepslate_iron_ore",
    332: "deepslate_gold_ore",
    333: "deepslate_redstone_ore",
    334: "deepslate_diamond_ore",
    335: "deepslate_lapis_ore",
    336: "deepslate_emerald_ore",
    337: "deepslate_copper_ore",
    338: "raw_iron_block",
    339: "raw_gold_block",
    340: "raw_copper_block",
    341: "powder_snow",
    342: "calibrated_sculk_sensor",
    343: "soul_soil",
    344: "nether_wart_block",
    345: "warped_wart_block",
    346: "warped_nylium",
    347: "crimson_nylium",
    348: "warped_roots",
    349: "crimson_roots",
    350: "nether_sprouts",
    351: "warped_fungus",
    352: "crimson_fungus",
    353: "warped_stem",
    354: "crimson_stem",
    355: "stripped_warped_stem",
    356: "stripped_crimson_stem",
    357: "warped_hyphae",
    358: "crimson_hyphae",
    359: "stripped_warped_hyphae",
    360: "stripped_crimson_hyphae",
    361: "warped_planks",
    362: "crimson_planks",
    363: "warped_slab",
    364: "crimson_slab",
    365: "warped_stairs",
    366: "crimson_stairs",
    367: "warped_fence",
    368: "crimson_fence",
    369: "warped_fence_gate",
    370: "crimson_fence_gate",
    371: "warped_door",
    372: "crimson_door",
    373: "warped_trapdoor",
    374: "crimson_trapdoor",
    375: "warped_sign",
    376: "crimson_sign",
    377: "warped_wall_sign",
    378: "crimson_wall_sign",
    379: "warped_button",
    380: "crimson_button",
    381: "warped_pressure_plate",
    382: "crimson_pressure_plate",
    383: "target",
    384: "lodestone",
    385: "respawn_anchor",
    386: "shroomlight",
    387: "crimson_nylium",
    388: "warped_nylium",
    389: "nether_bricks",
    390: "nether_brick_fence",
    391: "nether_brick_stairs",
    392: "nether_brick_slab",
    393: "nether_wart",
    394: "nether_quartz_ore",
    395: "nether_gold_ore",
    396: "ancient_debris",
    397: "netherite_block",
    398: "netherite_scrap",
    399: "netherite_ingot",
    400: "netherite_sword",
    401: "netherite_shovel",
    402: "netherite_pickaxe",
    403: "netherite_axe",
    404: "netherite_hoe",
    405: "netherite_helmet",
    406: "netherite_chestplate",
    407: "netherite_leggings",
    408: "netherite_boots",
    409: "netherite_horse_armor",
    410: "netherite_tnt",
    411: "netherite_bell",
    412: "netherite_block",
    413: "netherite_ore",
    414: "ancient_debris",
    415: "gilded_blackstone",
    416: "polished_blackstone",
    417: "polished_blackstone_bricks",
    418: "chiseled_polished_blackstone",
    419: "polished_blackstone_slab",
    420: "polished_blackstone_stairs",
    421: "polished_blackstone_wall",
    422: "polished_blackstone_brick_slab",
    423: "polished_blackstone_brick_stairs",
    424: "polished_blackstone_brick_wall",
    425: "polished_blackstone_button",
    426: "polished_blackstone_pressure_plate",
    427: "blackstone",
    428: "blackstone_slab",
    429: "blackstone_stairs",
    430: "blackstone_wall",
    431: "blackstone_button",
    432: "blackstone_pressure_plate",
    433: "blackstone_bricks",
    434: "blackstone_brick_slab",
    435: "blackstone_brick_stairs",
    436: "blackstone_brick_wall",
    437: "cracked_polished_blackstone_bricks",
    438: "gilded_blackstone",
    439: "chain",
    440: "netherite_scrap",
    441: "netherite_ingot",
    442: "netherite_block",
    443: "ancient_debris",
    444: "netherite_ore",
    445: "crying_obsidian",
    446: "respawn_anchor",
    447: "lodestone",
    448: "target",
    449: "netherite_tnt",
    450: "netherite_bell",
    451: "netherite_sword",
    452: "netherite_shovel",
    453: "netherite_pickaxe",
    454: "netherite_axe",
    455: "netherite_hoe",
    456: "netherite_helmet",
    457: "netherite_chestplate",
    458: "netherite_leggings",
    459: "netherite_boots",
    460: "netherite_horse_armor",
    461: "netherite_elytra",
    462: "netherite_shield",
    463: "netherite_trident",
    464: "netherite_rod",
    465: "netherite_block",
    466: "netherite_ore",
    467: "ancient_debris",
    468: "netherite_scrap",
    469: "netherite_ingot",
    470: "netherite_axe",
    471: "netherite_pickaxe",
    472: "netherite_shovel",
    473: "netherite_sword",
    474: "netherite_hoe",
    475: "netherite_helmet",
    476: "netherite_chestplate",
    477: "netherite_leggings",
    478: "netherite_boots",
    479: "netherite_horse_armor",
    480: "netherite_elytra",
    481: "netherite_shield",
    482: "netherite_trident",
    483: "netherite_rod",
    484: "netherite_block",
    485: "netherite_ore",
    486: "ancient_debris",
    487: "netherite_scrap",
    488: "netherite_ingot",
    489: "netherite_axe",
    490: "netherite_pickaxe",
    491: "netherite_shovel",
    492: "netherite_sword",
    493: "netherite_hoe",
    494: "netherite_helmet",
    495: "netherite_chestplate",
    496: "netherite_leggings",
    497: "netherite_boots",
    498: "netherite_horse_armor",
    499: "netherite_elytra",
    500: "netherite_shield",
    501: "netherite_trident",
    502: "netherite_rod"
}

# 反向映射：名称 -> ID
MINECRAFT_BLOCK_NAMES = {v: k for k, v in MINECRAFT_BLOCK_TYPES.items()}

# Minecraft 可通行方块类型列表
MINECRAFT_WALKABLE_BLOCKS = [
    0,   # 空气
    31,  # 草
    32,  # 蕨
    37,  # 蒲公英
    38,  # 虞美人
    59,  # 小麦
    63,  # 橡木板台阶
    64,  # 橡木门
    65,  # 梯子
    66,  # 铁轨
    67,  # 圆石台阶
    68,  # 墙火把
    69,  # 红石火把
    70,  # 红石粉尘
    71,  # 铁门
    72,  # 红石矿石
    75,  # 红石火把（激活）
    76,  # 按钮
    77,  # 石质压力板
    78,  # 雪
    79,  # 冰
    83,  # 甘蔗
    85,  # 栅栏
    90,  # 传送门方块
    92,  # 蛋糕
    96,  # 活板门
    106,  # 藤蔓
    114,  # 地狱砖台阶
    115,  # 末地传送门方块
    116,  # 末地传送门框架
    117,  # 龙蛋
    118,  # 红石比较器
    119,  # 红石比较器（激活）
    126,  # 陷阱箱
    131,  # 胡萝卜
    132,  # 马铃薯
    143,  # 命令方块
    147,  # 橡木栅栏门
    148,  # 云杉木台阶
    163,  # 金合欢木台阶
    164,  # 深色橡木台阶
    171,  # 末地烛
    175,  # 铁轨激活器
    176,  # 探测铁轨
    183,  # 铁栏杆
    184,  # 石砖台阶
    190,  # 活塞
    191,  # 粘性活塞
    192,  # 活塞臂
    193,  # 甘蔗
    194,  # 海带
    195,  # 干海带块
    196,  # 海泡菜
    197,  # 脚手架
    198,  # 脚手架
    199,  # 脚手架
    200,  # 脚手架
    201,  # 脚手架
    202,  # 脚手架
    203,  # 结构空位
    204,  # 铁潜影盒
    205,  # 金潜影盒
    206,  # 钻石潜影盒
    207,  # 绿宝石潜影盒
    208,  # 黑色潜影盒
    209,  # 红色潜影盒
    210,  # 绿色潜影盒
    211,  # 棕色潜影盒
    212,  # 蓝色潜影盒
    213,  # 紫色潜影盒
    214,  # 青色潜影盒
    215,  # 浅灰色潜影盒
    216,  # 灰色潜影盒
    217,  # 粉色潜影盒
    218,  # 品红色潜影盒
    219,  # 黄色潜影盒
    220,  # 黄绿色潜影盒
    221,  # 浅蓝色潜影盒
    222,  # 橙色潜影盒
    223,  # 白色潜影盒
    224,  # 旗帜
    225,  # 白色床
    226,  # 橙色床
    227,  # 品红色床
    228,  # 浅蓝色床
    229,  # 黄色床
    230,  # 黄绿色床
    231,  # 粉色床
    232,  # 灰色床
    233,  # 浅灰色床
    234,  # 青色床
    235,  # 紫色床
    236,  # 蓝色床
    237,  # 棕色床
    238,  # 绿色床
    239,  # 红色床
    240,  # 黑色床
    244,  # 链命令方块
    245,  # 竹子
    246,  # 竹子幼苗
    250,  # 木桶
    251,  # 烟熏炉
    252,  # 高炉
    253,  # 讲台
    254,  # 钟
    255,  # 堆肥桶
    256,  # 砂轮
    257,  # 切石机
    258,  # 制图台
    259,  # 制箭台
    260,  # 织布机
    261,  # 理发店
    262,  # 灯笼
    263,  # 营火
    264,  # 灵魂营火
    265,  # 讲台
    266,  # 蜂箱
    267,  # 蜂巢
    268,  # 蜂蜜块
    269,  # 蜜脾块
    270,  # 装饰性花盆
    271,  # 蜡烛
    272,  # 幽匿传感器
    273,  # 幽匿催化器
    274,  # 幽匿
    275,  # 幽匿脉络
    276,  # 幽匿尖叫者
    277,  # 校准后的幽匿传感器
    354,  # 诡异茎
    355,  # 去皮诡异茎
    356,  # 去皮绯红茎
    357,  # 诡异菌索
    358,  # 绯红菌索
    359,  # 去皮诡异菌索
    360,  # 去皮绯红菌索
    363,  # 诡异木板台阶
    364,  # 绯红木板台阶
    365,  # 诡异木板楼梯
    366,  # 绯红木板楼梯
    367,  # 诡异栅栏
    368,  # 绯红栅栏
    369,  # 诡异栅栏门
    370,  # 绯红栅栏门
    371,  # 诡异门
    372,  # 绯红门
    373,  # 诡异活板门
    374,  # 绯红活板门
    383,  # 目标
    384,  # 磁石
    385,  # 重生锚
    386,  # 发光地衣
    416,  # 抛光黑石
    417,  # 抛光黑石砖
    418,  # 錾制抛光黑石
    419,  # 抛光黑石台阶
    420,  # 抛光黑石楼梯
    421,  # 抛光黑石墙
    422,  # 抛光黑石砖台阶
    423,  # 抛光黑石砖楼梯
    424,  # 抛光黑石砖墙
    425,  # 裂纹抛光黑石砖
    437,  # 裂纹抛光黑石砖
    438,  # 镀金黑石
    439,  # 锁链
]


def get_minecraft_block_name(block_id: int) -> str:
    """根据方块 ID 获取 Minecraft 方块名称
    
    Args:
        block_id: 方块 ID
    
    Returns:
        str: 方块名称，未知 ID 返回 "unknown_{id}"
    """
    return MINECRAFT_BLOCK_TYPES.get(block_id, f"unknown_{block_id}")


def get_minecraft_block_id(block_name: str) -> int:
    """根据方块名称获取 Minecraft 方块 ID
    
    Args:
        block_name: 方块名称
    
    Returns:
        int: 方块 ID，未知名称返回 -1
    """
    return MINECRAFT_BLOCK_NAMES.get(block_name.lower(), -1)


def is_minecraft_walkable(block_id: int) -> bool:
    """判断 Minecraft 方块是否可通行
    
    Args:
        block_id: 方块 ID
    
    Returns:
        bool: 可通行返回 True
    """
    return block_id in MINECRAFT_WALKABLE_BLOCKS


def is_minecraft_solid(block_id: int) -> bool:
    """判断 Minecraft 方块是否为固体
    
    Args:
        block_id: 方块 ID
    
    Returns:
        bool: 固体返回 True
    """
    # 固体方块是指除了空气、液体、植物等之外的方块
    # 这里使用反向判断：如果不在可通行列表中，且不是特殊方块，就是固体
    return block_id not in MINECRAFT_WALKABLE_BLOCKS and block_id != 8 and block_id != 9  # 排除水


# ===== A* 路径寻找算法 =====
class Node:
    """A*算法节点类，用于表示地图上的位置"""
    def __init__(self, pos: Tuple[int, int, int], g: float = 0.0, h: float = 0.0, parent: Optional['Node'] = None):
        self.pos = pos  # (x, y, z) 坐标
        self.g = g      # 从起点到当前节点的实际代价
        self.h = h      # 从当前节点到目标节点的估计代价（启发式）
        self.parent = parent  # 父节点，用于路径重建
    
    @property
    def f(self) -> float:
        """总代价 = 实际代价 + 估计代价"""
        return self.g + self.h
    
    def __lt__(self, other: 'Node') -> bool:
        """用于优先队列排序，f值较小的节点优先级更高"""
        return self.f < other.f
    
    def __eq__(self, other: 'Node') -> bool:
        """节点相等判断，基于位置坐标"""
        return self.pos == other.pos
    
    def __hash__(self) -> int:
        """节点哈希值，基于位置坐标"""
        return hash(self.pos)


def heuristic(a: Tuple[int, int, int], b: Tuple[int, int, int], use_manhattan: bool = False) -> float:
    """启发式函数，计算两个位置之间的估计代价
    
    Args:
        a: 位置A (x, y, z)
        b: 位置B (x, y, z)
        use_manhattan: 是否使用曼哈顿距离，否则使用欧几里得距离
    
    Returns:
        float: 估计代价
    """
    dx = abs(a[0] - b[0])
    dy = abs(a[1] - b[1])
    dz = abs(a[2] - b[2])
    
    if use_manhattan:
        # 曼哈顿距离：只允许上下左右前后移动
        return dx + dy + dz
    else:
        # 欧几里得距离：允许对角线移动
        return math.sqrt(dx**2 + dy**2 + dz**2)


def get_neighbors(pos: Tuple[int, int, int], allow_diagonal: bool = True) -> List[Tuple[int, int, int]]:
    """获取当前位置的相邻节点
    
    Args:
        pos: 当前位置 (x, y, z)
        allow_diagonal: 是否允许对角线移动
    
    Returns:
        List[Tuple[int, int, int]]: 相邻节点列表
    """
    x, y, z = pos
    neighbors = []
    
    # 基本方向：上下左右前后
    directions = [
        (0, 1, 0), (0, -1, 0),  # 上下
        (1, 0, 0), (-1, 0, 0),  # 左右
        (0, 0, 1), (0, 0, -1),  # 前后
    ]
    
    # 添加基本方向的邻居
    for dx, dy, dz in directions:
        neighbors.append((x + dx, y + dy, z + dz))
    
    # 如果允许对角线移动，添加对角线方向
    if allow_diagonal:
        diagonal_directions = [
            (1, 1, 0), (-1, 1, 0), (1, -1, 0), (-1, -1, 0),  # 水平对角线
            (1, 0, 1), (-1, 0, 1), (1, 0, -1), (-1, 0, -1),  # 前后对角线
            (0, 1, 1), (0, -1, 1), (0, 1, -1), (0, -1, -1),  # 垂直对角线
            (1, 1, 1), (-1, 1, 1), (1, -1, 1), (-1, -1, 1),  # 三维对角线
            (1, 1, -1), (-1, 1, -1), (1, -1, -1), (-1, -1, -1),
        ]
        for dx, dy, dz in diagonal_directions:
            neighbors.append((x + dx, y + dy, z + dz))
    
    return neighbors


def is_walkable(pos: Tuple[int, int, int], game_state: Dict[Tuple[int, int, int], int], game_type: str = "minecraft") -> bool:
    """判断一个位置是否可通行
    
    Args:
        pos: 位置 (x, y, z)
        game_state: 游戏状态，{(x,y,z): block_type}
        game_type: 游戏类型，用于选择不同的可通行性规则
    
    Returns:
        bool: 可通行返回 True
    """
    # 获取当前位置的方块类型
    block_type = game_state.get(pos, 0)
    
    if game_type == "minecraft":
        # Minecraft 特定的可通行性判断
        # 检查当前位置是否可通行
        if not is_minecraft_walkable(block_type):
            return False
        
        # 检查脚下是否有支撑（防止悬空）
        under_pos = (pos[0], pos[1] - 1, pos[2])
        under_block = game_state.get(under_pos, 0)
        if under_block == 0:  # 脚下是空气
            # 检查是否可以跳跃到这个位置
            jump_from = (pos[0], pos[1] - 2, pos[2])
            jump_block = game_state.get(jump_from, 0)
            if not is_minecraft_solid(jump_block):
                return False
        
        # 检查头顶是否有足够空间（防止窒息）
        head_pos = (pos[0], pos[1] + 1, pos[2])
        head_block = game_state.get(head_pos, 0)
        if is_minecraft_solid(head_block):
            return False
        
        return True
    else:
        # 通用可通行性判断
        # 获取当前位置的方块类型
        block_type = game_state.get(pos, 0)
        
        # 检查当前位置是否可通行
        if block_type != 0:  # 非空气方块
            return False
        
        # 检查脚下是否有支撑（防止悬空）
        under_pos = (pos[0], pos[1] - 1, pos[2])
        under_block = game_state.get(under_pos, 0)
        if under_block == 0:  # 脚下是空气
            return False
        
        return True


def a_star_search(
    start: Tuple[int, int, int],
    goal: Tuple[int, int, int],
    game_state: Dict[Tuple[int, int, int], int],
    game_type: str = "minecraft",
    allow_diagonal: bool = True,
    max_iterations: int = 10000,
    use_manhattan: bool = False
) -> Optional[List[Tuple[int, int, int]]]:
    """A*路径寻找算法实现
    
    Args:
        start: 起点位置 (x, y, z)
        goal: 目标位置 (x, y, z)
        game_state: 游戏状态，{(x,y,z): block_type}
        game_type: 游戏类型，用于选择不同的可通行性规则
        allow_diagonal: 是否允许对角线移动
        max_iterations: 最大迭代次数，防止无限循环
        use_manhattan: 是否使用曼哈顿距离作为启发式函数
    
    Returns:
        Optional[List[Tuple[int, int, int]]]: 找到的路径，从起点到目标点，未找到返回 None
    """
    import heapq
    
    # 检查起点和目标点是否可通行
    if not is_walkable(start, game_state, game_type) or not is_walkable(goal, game_state, game_type):
        warn(f"起点或目标点不可通行: 起点={start}, 目标={goal}")
        return None
    
    # 初始化开放列表（优先队列）和关闭列表
    open_set = []
    heapq.heappush(open_set, Node(start, 0, heuristic(start, goal, use_manhattan)))
    closed_set = set()
    
    # 记录每个位置的最佳节点
    came_from: Dict[Tuple[int, int, int], Node] = {}
    g_score: Dict[Tuple[int, int, int], float] = {start: 0.0}
    
    # 优化：提前终止条件 - 当到达目标点附近时
    goal_radius = 1  # 允许的误差范围
    
    iterations = 0
    while open_set and iterations < max_iterations:
        iterations += 1
        
        # 获取f值最小的节点
        current_node = heapq.heappop(open_set)
        current_pos = current_node.pos
        
        # 检查是否到达目标点或目标点附近
        dx = abs(current_pos[0] - goal[0])
        dy = abs(current_pos[1] - goal[1])
        dz = abs(current_pos[2] - goal[2])
        if dx <= goal_radius and dy <= goal_radius and dz <= goal_radius:
            path = []
            while current_node:
                path.append(current_node.pos)
                current_node = current_node.parent
            return path[::-1]  # 反转路径，从起点到目标点
        
        # 将当前节点加入关闭列表
        closed_set.add(current_pos)
        
        # 检查所有邻居
        for neighbor_pos in get_neighbors(current_pos, allow_diagonal):
            # 跳过已处理的节点
            if neighbor_pos in closed_set:
                continue
            
            # 检查邻居是否可通行
            if not is_walkable(neighbor_pos, game_state, game_type):
                continue
            
            # 计算从起点到邻居的临时代价
            # 基本移动代价为1，对角线移动代价为√2
            if allow_diagonal and sum(abs(a - b) for a, b in zip(current_pos, neighbor_pos)) > 1:
                tentative_g = g_score[current_pos] + math.sqrt(2)
            else:
                tentative_g = g_score[current_pos] + 1.0
            
            # 如果这条路径更差，跳过
            if neighbor_pos in g_score and tentative_g >= g_score[neighbor_pos]:
                continue
            
            # 这条路径更好，更新信息
            neighbor_node = Node(neighbor_pos, tentative_g, heuristic(neighbor_pos, goal, use_manhattan), current_node)
            came_from[neighbor_pos] = neighbor_node
            g_score[neighbor_pos] = tentative_g
            
            # 将邻居节点加入开放列表
            heapq.heappush(open_set, neighbor_node)
    
    # 达到最大迭代次数或无法找到路径
    warn(f"A*搜索未找到路径，迭代次数: {iterations}")
    return None


def parse_game_state_from_region(region: bytes, stride: int, fields: Dict[str, int], bounds: Dict[str, List[int]]) -> Dict[Tuple[int, int, int], int]:
    out: Dict[Tuple[int, int, int], int] = {}
    x_off = fields.get("x", 0)
    y_off = fields.get("y", 4)
    z_off = fields.get("z", 8)
    t_off = fields.get("type", 12)
    rlen = len(region)
    i = 0
    x_min, x_max = bounds.get("x", [-4096, 4096])
    y_min, y_max = bounds.get("y", [-4096, 4096])
    z_min, z_max = bounds.get("z", [-4096, 4096])
    t_min, t_max = bounds.get("type", [0, 4096])
    while i + max(x_off, y_off, z_off, t_off) + 4 <= rlen:
        x = int.from_bytes(region[i + x_off : i + x_off + 4], "little", signed=True)
        y = int.from_bytes(region[i + y_off : i + y_off + 4], "little", signed=True)
        z = int.from_bytes(region[i + z_off : i + z_off + 4], "little", signed=True)
        bt = int.from_bytes(region[i + t_off : i + t_off + 4], "little", signed=False)
        if x_min <= x <= x_max and y_min <= y <= y_max and z_min <= z <= z_max and t_min <= bt <= t_max:
            out[(x, y, z)] = bt
        i += stride
    return out


def load_blueprint(path: str) -> Dict[Tuple[int, int, int], int]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out: Dict[Tuple[int, int, int], int] = {}
    for block in data:
        if isinstance(block, dict) and "pos" in block and "type" in block:
            x, y, z = block["pos"]
            out[(int(x), int(y), int(z))] = int(block["type"])
        elif isinstance(block, list) and len(block) >= 4:
            try:
                x, y, z = block[2]
                btype = block[3][0]
                out[(int(x), int(y), int(z))] = int(btype)
            except Exception:
                continue
    return out


def place_block(libc, task: int, config: dict, x: int, y: int, z: int, btype: int) -> None:
    pconf = config["placement"]
    base_addr = parse_int_auto(pconf["buffer_address"])
    fields = pconf.get("fields", {"x": 0, "y": 4, "z": 8, "type": 12})
    override = bool(pconf.get("override_protection", False))
    trigger = pconf.get("trigger", {"address": None, "value": 1, "size": 4})

    # 构造结构体字节
    max_off = max(fields.get("x", 0), fields.get("y", 4), fields.get("z", 8), fields.get("type", 12))
    buf_len = max_off + 4
    buf = bytearray(buf_len)
    buf[fields.get("x", 0) : fields.get("x", 0) + 4] = int(x).to_bytes(4, "little", signed=True)
    buf[fields.get("y", 4) : fields.get("y", 4) + 4] = int(y).to_bytes(4, "little", signed=True)
    buf[fields.get("z", 8) : fields.get("z", 8) + 4] = int(z).to_bytes(4, "little", signed=True)
    buf[fields.get("type", 12) : fields.get("type", 12) + 4] = int(btype).to_bytes(4, "little", signed=False)

    if override:
        ensure_writable(libc, task, base_addr, buf_len)
    write_memory(libc, task, base_addr, bytes(buf))

    # 触发放置（如写入标志/队列长度/事件值）
    t_addr = trigger.get("address")
    if t_addr:
        t_addr_i = parse_int_auto(t_addr)
        t_val = int(trigger.get("value", 1))
        t_size = int(trigger.get("size", 4))
        if override:
            ensure_writable(libc, task, t_addr_i, t_size)
        write_memory(libc, task, t_addr_i, t_val.to_bytes(t_size, "little", signed=False))


def place_block_via_state(libc, task: int, pos_to_addr: Dict[Tuple[int, int, int], int], x: int, y: int, z: int, btype: int) -> bool:
    """无 placement 缓冲时的回退：直接向状态区域对应记录写入 type。成功返回 True。"""
    addr = pos_to_addr.get((x, y, z))
    if addr is None:
        return False
    try:
        ensure_writable(libc, task, addr + 12, 4)
        write_memory(libc, task, addr + 12, int(btype).to_bytes(4, 'little', signed=False))
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="macOS 内存读取 + 自动放置（PoC）")
    ap.add_argument("--pid", type=int, help="目标进程 PID")
    ap.add_argument("--name", type=str, help="目标进程名（精确匹配二进制名）")
    ap.add_argument("--config", type=str, default="memory_layout.json", help="内存布局配置 JSON")
    ap.add_argument("--limit", type=int, default=10000, help="最多放置的方块数量（安全限幅）")
    ap.add_argument("--dry-run", action="store_true", help="只打印差异，不进行写入")
    ap.add_argument("--auto", action="store_true", help="自动选择目标进程（前台或配置匹配）")
    ap.add_argument("--show-ports", action="store_true", help="显示目标进程的网络端口信息")
    ap.add_argument("--port", type=int, help="按端口自动选择进程（无 --pid/--name 时生效）")
    ap.add_argument("--proto", type=str, choices=["tcp", "udp"], help="与 --port 搭配的协议过滤")
    ap.add_argument("--auto-state", action="store_true", help="自动扫描进程内存以构建游戏状态（跳过 state_region 配置）")
    ap.add_argument("--auto-state-limit-mb", type=int, default=128, help="自动扫描的读取上限（MB）")
    ap.add_argument("--auto-all", action="store_true", help="一键自动：自动状态扫描、差异放置；缺少 placement 时直接写入 state；尝试自动发现 movement")
    args = ap.parse_args()

    pid = args.pid or 0
    if not pid and args.name:
        pid = find_pid_by_name(args.name)

    # 端口选择
    if not pid and args.port:
        pid = find_pid_by_port(args.port, args.proto) or 0

    # 自动选择目标进程
    if not pid and args.auto:
        # 需要先读取配置用于 patterns
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg_for_auto = json.load(f)
        except Exception:
            cfg_for_auto = {}
        pid = auto_detect_pid(cfg_for_auto) or 0

    if not pid:
        error("未提供 --pid，--name 或无法自动选择进程（--auto）。")
        sys.exit(1)

    # 读取配置
    try:
        with open(args.config, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        error(f"配置读取失败：{e}")
        sys.exit(2)

    # 蓝图
    blueprint = load_blueprint("blueprint.json")
    info(f"蓝图条目：{len(blueprint)}")

    # 蓝图类型不再生成映射模板：脚本依赖游戏的官方类型映射（数值 ID）。

    # 初始化 Mach 接口（始终内存读写）
    libc = load_libc()
    setup_prototypes(libc)
    task = get_task(libc, pid)

    if args.show_ports:
        ports = list_open_ports(pid)
        if ports:
            info("进程网络端口（lsof）：")
            for ln in ports[:50]:
                print("  ", ln)
        else:
            info("未能获取端口信息或无活动网络连接")

    # 读取状态（配置 or 自动扫描）
    game_state: Dict[Tuple[int, int, int], int] = {}
    pos_to_addr: Dict[Tuple[int, int, int], int] = {}
    if args.auto_state or args.auto_all:
        info(f"自动扫描进程内存构建游戏状态，上限 {args.auto_state_limit_mb} MB")
        try:
            game_state, pos_to_addr = auto_scan_state(libc, task, limit_mb=args.auto_state_limit_mb)
        except Exception as e:
            error(f"自动扫描失败：{e}")
            sys.exit(4)
    else:
        sconf = config.get("state_region")
        if not sconf:
            error("配置缺少 state_region")
            sys.exit(3)
        base = parse_int_auto(sconf["address"])
        size = int(sconf["size"])
        stride = int(sconf.get("stride", 16))
        fields = sconf.get("fields", {"x": 0, "y": 4, "z": 8, "type": 12})
        bounds = sconf.get("bounds", {"x": [-4096, 4096], "y": [-4096, 4096], "z": [-4096, 4096], "type": [0, 4096]})

        try:
            region = read_memory(libc, task, base, size)
        except Exception as e:
            error(f"状态区域读取失败：{e}")
            sys.exit(4)

        game_state = parse_game_state_from_region(region, stride, fields, bounds)
    info(f"游戏状态候选条目：{len(game_state)}")

    # 计算差异
    missing = []
    mismatch = []
    for pos, btype in blueprint.items():
        gt = game_state.get(pos)
        if gt is None:
            missing.append((pos, btype))
        elif gt != btype:
            mismatch.append((pos, btype))

    info(f"差异统计：missing={len(missing)} mismatch={len(mismatch)}")

    if args.dry_run:
        info("跳过写入，仅展示前 20 条差异示例：")
        for i, (pos, bt) in enumerate(missing[:20]):
            info(f"  MISSING {pos} => type {bt}")
        for i, (pos, bt) in enumerate(mismatch[:20]):
            info(f"  MISMATCH {pos} => type {bt}")
        sys.exit(0)

    # 自动发现 movement（在 auto-all 模式且配置缺失时尝试）
    if args.auto_all and not config.get("movement") and (missing or mismatch):
        try:
            first_pos = (missing or mismatch)[0][0]
            x, y, z = first_pos
            off = [0.5, 0.0, 0.5]
            target_front = (float(x) + off[0], float(y) + off[1], float(z) + off[2])
            info("尝试自动发现 movement 地址（写入测试有风险）...")
            m_auto = discover_movement(libc, task, target_front, max_attempts=64)
            if m_auto:
                config["movement"] = m_auto
                info(f"movement 发现成功：地址 {m_auto['move_to']['address']}")
            else:
                info("未能自动发现 movement，继续使用直接写入 state 的方式放置")
        except Exception as e:
            warn(f"自动发现 movement 过程异常：{e}")

    # 执行放置（先处理缺失，再处理不匹配）
    placed = 0
    
    # 为移动模块添加游戏状态信息
    config["game_state"] = game_state
    
    # 初始化移动模块管理器
    movement_manager = MovementModuleManager()
    movement_module = movement_manager.initialize(libc, task, config)
    
    # 加载 CoreGraphics 库用于键盘模拟
    cg_lib = load_cgevent()
    
    for pos, bt in missing + mismatch:
        if placed >= args.limit:
            info(f"已达安全限额 {args.limit}，停止写入")
            break
        x, y, z = pos
        try:
            # 若配置了 movement，则先移动到目标前并校准视角
            mconf = config.get("movement")
            if mconf:
                off = mconf.get("approach_offset", [0.5, 0.0, 0.5])
                try:
                    dx, dy, dz = float(off[0]), float(off[1]), float(off[2])
                except Exception:
                    dx, dy, dz = 0.5, 0.0, 0.5
                target_front = (float(x) + dx, float(y) + dy, float(z) + dz)
                
                # 使用移动模块进行移动
                moved = movement_module.move_to(libc, cg_lib, task, config, target_front)
                if moved:
                    arrived = movement_wait_arrival(libc, task, config, target_front)
                    ppos = movement_module.read_player_pos(libc, task, config)
                    # 视角校准到方块中心（y+0.5）
                    aim_target = (float(x) + 0.5, float(y) + 0.5, float(z) + 0.5)
                    movement_module.aim_at(libc, cg_lib, task, config, ppos, aim_target)
            # 放置：优先使用 placement；缺失或失败则回退到直接写 state
            if config.get("placement"):
                try:
                    place_block(libc, task, config, x, y, z, bt)
                except Exception as e:
                    ok = False
                    if pos_to_addr:
                        ok = place_block_via_state(libc, task, pos_to_addr, x, y, z, bt)
                    if not ok:
                        raise e
            else:
                ok = place_block_via_state(libc, task, pos_to_addr, x, y, z, bt)
                if not ok:
                    raise RuntimeError("无 placement 且状态映射缺失，无法写入")
            placed += 1
            # 小延时避免过快写入引发问题（根据实际调整）
            time.sleep(0.01)
        except Exception as e:
            error(f"写入失败 {pos},{bt}：{e}")

    info(f"放置尝试完成：{placed} 条")


if __name__ == "__main__":
    main()

