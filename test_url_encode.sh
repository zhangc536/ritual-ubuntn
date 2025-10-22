#!/bin/bash

# 测试修复后的 url_encode 函数
url_encode() {
  python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

# 测试各种输入
echo "测试 url_encode 函数："
echo "原始字符串: 'hello world'"
echo "编码结果: $(url_encode 'hello world')"
echo
echo "原始字符串: 'test@example.com'"
echo "编码结果: $(url_encode 'test@example.com')"
echo
echo "原始字符串: 'password123!@#'"
echo "编码结果: $(url_encode 'password123!@#')"
echo
echo "测试完成！"
