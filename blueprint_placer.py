#!/usr/bin/env python3
import json
import pyautogui
import time


# 读取蓝图文件并按坐标自动点击放置

def world_to_screen(x: float, y: float, z: float) -> tuple:
    """将世界坐标映射为屏幕坐标（请按窗口比例自行调整）。"""
    screen_x = 100 + x * 10
    screen_y = 200 - z * 10
    return screen_x, screen_y


def main():
    # 读取蓝图文件
    with open('blueprint.json', 'r', encoding='utf-8') as f:
        blueprint = json.load(f)

    # 遍历每个方块
    for block in blueprint:
        x, y, z = block[2]        # 世界坐标
        block_type = block[3][0]  # 方块类型
        action = block[4]         # "P" 表示放置

        if action == "P":
            # 将世界坐标转换为屏幕坐标（需要你根据窗口比例映射）
            screen_x, screen_y = world_to_screen(x, y, z)
            pyautogui.moveTo(screen_x, screen_y)
            pyautogui.click()
            time.sleep(0.01)  # 放置间隔


if __name__ == "__main__":
    # 移动到屏幕左上角可触发 FailSafe 异常快速中止（pyautogui 默认开启）
    pyautogui.FAILSAFE = True
    main()

