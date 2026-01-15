# GitHub Pages 部署指南

## 配置完成 ✅

你的 Docusaurus 站点已经配置好了！

- **GitHub 用户名**: lizisec
- **仓库名**: lizisec.github.io
- **站点地址**: https://lizisec.github.io

## 部署步骤

### 1. 在 GitHub 仓库中启用 GitHub Pages

1. 进入你的 GitHub 仓库：https://github.com/lizisec/lizisec.github.io
2. 点击 **Settings** (设置)
3. 在左侧菜单找到 **Pages**
4. 在 **Source** (来源) 下选择 **GitHub Actions**

### 2. 推送代码

```bash
git add .
git commit -m "配置 GitHub Pages 部署"
git push origin main
```

### 3. 查看部署状态

1. 进入仓库的 **Actions** 标签页：https://github.com/lizisec/lizisec.github.io/actions
2. 查看 "Deploy to GitHub Pages" 工作流的运行状态
3. 部署成功后，访问 https://lizisec.github.io

## 本地开发

```bash
# 启动开发服务器（热重载）
npm start

# 构建生产版本
npm run build

# 预览生产版本
npm run serve
```

## 管理你的笔记

### 添加文档

在 `docs/` 目录下创建或编辑 Markdown 文件：

```bash
docs/
  ├── intro.md
  ├── 你的笔记分类/
  │   ├── _category_.json
  │   └── 笔记1.md
  └── ...
```

### 添加博客文章

在 `blog/` 目录下创建 Markdown 文件：

```bash
blog/
  └── 2026-01-15-文章标题.md
```

文章开头需要添加 frontmatter：

```markdown
---
title: 文章标题
authors: [你的名字]
tags: [标签1, 标签2]
---

文章内容...
```

## 注意事项

- 确保你的主分支名称是 `main`（如果是 `master`，需要修改 `.github/workflows/deploy.yml` 中的分支名）
- 首次部署可能需要几分钟时间
- 每次推送到 main 分支都会自动触发部署
- 因为你使用的是 `username.github.io` 仓库，站点会直接部署到根路径
