# SecShrimp Knowledge Hub

安全虾知识库网站 — 动态加载，实时同步。

## 特性

- ✅ 运行时加载 .md 文件
- ✅ 修改知识库文件后网站自动更新
- ✅ 响应式设计，支持移动端
- ✅ 自动部署到 GitHub Pages

## 目录结构

```
kb-site/
├── index.html              # 主页面（动态加载）
├── sync.sh                 # 同步脚本
├── security/               # 安全知识（从 knowledge/ 同步）
│   ├── attack-techniques.md
│   ├── defense-strategies.md
│   ├── llm-security.md
│   └── ...
├── malware-detect/         # 恶意下载检测文档
│   ├── README.md
│   └── DESIGN.md
└── .github/workflows/      # GitHub Actions
    └── deploy.yml
```

## 使用方法

### 本地预览

```bash
cd kb-site
python -m http.server 8000
# 访问 http://localhost:8000
```

### 同步知识库

```bash
bash sync.sh
```

### 部署到 GitHub Pages

1. 创建 GitHub 仓库 `secshrimp-kb`
2. 推送代码
3. 在仓库设置中启用 GitHub Pages（Source: GitHub Actions）

```bash
cd kb-site
git init
git add -A
git commit -m "Initial commit"
git remote add origin git@github.com:DarkWebHunter99/secshrimp-kb.git
git push -u origin main
```

## 更新知识库

1. 编辑 `.openclaw/workspace/knowledge/security/` 下的文件
2. 运行 `bash sync.sh` 同步到网站目录
3. 提交并推送到 GitHub
4. GitHub Actions 自动部署

## 访问地址

部署完成后访问：`https://darkwebhunter99.github.io/secshrimp-kb/`
