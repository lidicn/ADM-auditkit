#!/usr/bin/env bash
# [D-42] rm -rf 作用于变量 —— 变量为空即删根目录
TARGET="$1"
rm -rf ${TARGET}/build

# [D-43] 硬编码口令
PASSWORD="hunter2supersecret"
echo "connecting with $PASSWORD"
