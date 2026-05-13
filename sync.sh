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

# 生成模板目录 README.md
echo ""
echo "📝 生成模板目录索引..."

generate_template_readme() {
    local dir="$1"
    local title="$2"
    local desc="$3"
    local readme="$dir/README.md"

    cat > "$readme" <<HEADER
# $title

$desc

| 文件 | 类型 | 说明 |
|------|------|------|
HEADER

    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        local fname=$(basename "$f")
        [ "$fname" = "README.md" ] && continue

        local ext="${fname##*.}"
        local name="${fname%.*}"
        local ftype=""
        local note=""

        case "$ext" in
            py)     ftype="Python" ;;
            yaml|yml) ftype="Sigma/YAML" ;;
            yar)    ftype="YARA" ;;
            rules)  ftype="Suricata" ;;
            json)   ftype="JSON" ;;
            go)     ftype="Go" ;;
            ps1)    ftype="PowerShell" ;;
            md)     ftype="Markdown" ;;
            *)      ftype="$ext" ;;
        esac

        # 从文件提取简要说明
        case "$ext" in
            py)
                note=$(head -20 "$f" | grep -m1 '"""' -A1 2>/dev/null | tail -1 | head -c 80)
                [ -z "$note" ] && note=$(head -5 "$f" | grep -m1 '^#' | sed 's/^#\s*//' | head -c 80)
                ;;
            yaml|yml)
                note=$(grep -m1 '^title:' "$f" 2>/dev/null | sed 's/^title:\s*//' | head -c 80)
                [ -z "$note" ] && note=$(grep -m1 '^description:' "$f" 2>/dev/null | sed 's/^description:\s*//' | head -c 80)
                ;;
            yar)
                note=$(grep -m1 '^meta:' -A5 "$f" 2>/dev/null | grep -m1 'description' | sed 's/.*description\s*=\s*//' | tr -d '"' | head -c 80)
                ;;
            rules)
                note=$(grep -m1 '^# ' "$f" 2>/dev/null | sed 's/^#\s*//' | head -c 80)
                ;;
        esac
        [ -z "$note" ] && note="$name"

        echo "| \`$fname\` | $ftype | $note |" >> "$readme"
    done

    echo "" >> "$readme"
    echo "_自动生成于 $(date '+%Y-%m-%d')_" >> "$readme"
}

generate_template_readme "$SCRIPT_DIR/codeshrimp/templates/ai-security" \
    "AI/LLM 安全模板" \
    "AI 系统安全测试工具集，包含 Prompt 注入、Agent 安全审计、MCP 工具审计等。"

generate_template_readme "$SCRIPT_DIR/codeshrimp/templates/detection" \
    "检测规则模板" \
    "Sigma / YARA / Suricata 检测规则模板库，覆盖 MITRE ATT&CK 常见技术。"

generate_template_readme "$SCRIPT_DIR/codeshrimp/templates/network" \
    "网络安全工具" \
    "网络层安全工具：端口扫描、子域名枚举、横向移动检测等。"

generate_template_readme "$SCRIPT_DIR/codeshrimp/templates/web" \
    "Web 安全工具" \
    "Web 应用安全测试工具：SQLi、XSS、SSRF、WAF 绕过、反序列化、API 安全。"

generate_template_readme "$SCRIPT_DIR/codeshrimp/templates/utils" \
    "通用工具库" \
    "安全脚本通用组件：HTTP 客户端、报告生成器、异步扫描框架、安全库参考。"

echo "✅ 模板目录索引生成完成"

# 清理 __pycache__
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null

echo ""
echo "📊 同步统计:"
echo "   安全虾: $(find "$SCRIPT_DIR/secshrimp" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo "   代码虾: $(find "$SCRIPT_DIR/codeshrimp" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo "   共享: $(find "$SCRIPT_DIR/shared" -name "*.md" 2>/dev/null | wc -l) 个文件"
echo ""
echo "🦐 同步完成！"
