#!/bin/bash
# 同步知识库文件到网站目录
# 用法: bash sync.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KNOWLEDGE_DIR="../.openclaw/workspace/knowledge"

echo "🦐 同步知识库文件..."

# 同步安全知识
cp -v "$KNOWLEDGE_DIR/security/"*.md "$SCRIPT_DIR/security/" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 安全知识同步完成"
else
    echo "❌ 安全知识同步失败"
fi

# 同步恶意下载检测引擎文档
cp -v "$KNOWLEDGE_DIR/malware-detect/README.md" "$SCRIPT_DIR/malware-detect/" 2>/dev/null
cp -v "$KNOWLEDGE_DIR/malware-detect/DESIGN.md" "$SCRIPT_DIR/malware-detect/" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 恶意下载检测文档同步完成"
else
    echo "❌ 恶意下载检测文档同步失败"
fi

echo ""
echo "📊 同步统计:"
echo "   安全知识: $(ls -1 "$SCRIPT_DIR/security/"*.md 2>/dev/null | wc -l) 个文件"
echo "   检测引擎: $(ls -1 "$SCRIPT_DIR/malware-detect/"*.md 2>/dev/null | wc -l) 个文件"
echo ""
echo "🦐 同步完成！"
