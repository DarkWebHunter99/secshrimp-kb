#!/bin/bash
# 同步知识库文件到网站目录
# 用法: bash sync.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KNOWLEDGE_DIR="../.openclaw/workspace/knowledge"

echo "🦐 同步知识库文件..."

# 同步安全虾知识
mkdir -p "$SCRIPT_DIR/secshrimp"
cp -v "$KNOWLEDGE_DIR/secshrimp/"*.md "$SCRIPT_DIR/secshrimp/" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 安全虾知识同步完成"
else
    echo "❌ 安全虾知识同步失败"
fi

# 同步代码虾知识
mkdir -p "$SCRIPT_DIR/codeshrimp"
cp -v "$KNOWLEDGE_DIR/codeshrimp/"*.md "$SCRIPT_DIR/codeshrimp/" 2>/dev/null
cp -rv "$KNOWLEDGE_DIR/codeshrimp/templates" "$SCRIPT_DIR/codeshrimp/" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 代码虾知识同步完成"
else
    echo "❌ 代码虾知识同步失败"
fi

# 同步共享知识
mkdir -p "$SCRIPT_DIR/shared"
cp -rv "$KNOWLEDGE_DIR/shared/"* "$SCRIPT_DIR/shared/" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 共享知识同步完成"
else
    echo "❌ 共享知识同步失败"
fi

# 同步总索引
cp -v "$KNOWLEDGE_DIR/index.md" "$SCRIPT_DIR/" 2>/dev/null

echo ""
echo "📊 同步统计:"
echo "   安全虾: $(find "$SCRIPT_DIR/secshrimp" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo "   代码虾: $(find "$SCRIPT_DIR/codeshrimp" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo "   共享: $(find "$SCRIPT_DIR/shared" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo ""
echo "🦐 同步完成！"
