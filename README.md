这是一个使用 Jekyll 构建的个人笔记站点，部署在 GitHub Pages 上。  
内容包含 Hack The Box / VulnHub 靶机复盘与协议利用笔记。

🌐 **在线访问**: https://lizisec.github.io

## 本地运行

```bash
bundle install
bundle exec jekyll serve
```

默认地址：`http://127.0.0.1:4000`

建议环境：Ruby `>= 3.0`（macOS 系统自带 Ruby 2.6 可能无法安装新依赖）。

## 内容结构

- `_posts/`: 首页文章流（博客）
- `notes/`: 靶机笔记（每个目录一个 `index.md` + 图片资源）
- `notes.html`: 靶机维度总览（平台/系统/难度/方向/状态）
- `tags.html`: 文章标签 + 靶机标签索引页

## 标签规范（已统一）

- 文章标签：协议、漏洞、利用场景（例：`协议-SSH`、`漏洞-CVE-2018-15473`）
- 靶机标签：结构化维度（例：`平台-HTB`、`系统-Windows`、`难度-Hard`、`方向-AD`、`状态-WIP`）
- 专题标签：保留具体技术点（例：`专题-GPP`、`专题-JuicyPotato`）
