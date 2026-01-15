# 我的笔记站点

这是一个使用 Docusaurus 构建的个人笔记站点，部署在 GitHub Pages 上。

🌐 **在线访问**: https://lizisec.github.io

## 功能特性

- 📚 文档管理：系统化的笔记组织
- 📝 博客系统：技术文章分享
- 🎨 主题切换：支持亮色/暗色模式
- 📱 响应式设计：完美支持移动端
- 🔍 全文搜索：快速查找内容（可选配置）
- 📊 自动部署：推送代码自动更新站点

## 本地开发

### 安装依赖

```bash
npm install
```

### 启动开发服务器

```bash
npm start
```

访问 http://localhost:3000 查看站点。

### 构建生产版本

```bash
npm run build
```

### 预览生产版本

```bash
npm run serve
```

## 添加内容

### 添加文档

在 `docs/` 目录下创建 Markdown 文件：

```
docs/
  ├── intro.md
  ├── 分类名称/
  │   ├── _category_.json
  │   └── 文档名称.md
  └── ...
```

### 添加博客文章

在 `blog/` 目录下创建 Markdown 文件：

```
blog/
  └── YYYY-MM-DD-文章标题.md
```

文章格式：

```markdown
---
slug: article-slug
title: 文章标题
authors: [lizisec]
tags: [标签1, 标签2]
---

文章摘要

<!-- truncate -->

文章正文...
```

## 部署

推送代码到 GitHub 会自动触发部署：

```bash
git add .
git commit -m "更新内容"
git push
```

查看部署状态：https://github.com/lizisec/lizisec.github.io/actions

## 技术栈

- [Docusaurus](https://docusaurus.io/) - 静态站点生成器
- [React](https://reactjs.org/) - UI 框架
- [TypeScript](https://www.typescriptlang.org/) - 类型安全
- [GitHub Actions](https://github.com/features/actions) - CI/CD
- [GitHub Pages](https://pages.github.com/) - 托管服务

## 许可证

MIT License
