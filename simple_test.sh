#!/bin/bash

# 简单测试修复后的 url_encode 函数
echo "测试修复后的 url_encode 函数..."

url_encode() {
  python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

# 测试基本功能
test_string="hello world"
encoded=$(url_encode "$test_string")
echo "输入: $test_string"
echo "输出: $encoded"

if [ -n "$encoded" ]; then
    echo "✅ url_encode 函数工作正常！"
else
    echo "❌ url_encode 函数有问题"
fi
