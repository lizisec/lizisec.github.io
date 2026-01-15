# 使用指南

## 快速开始

### 1. 本地预览

```bash
npm start
```

浏览器会自动打开 http://localhost:3000

### 2. 添加笔记

#### 创建新的文档分类

```bash
mkdir -p docs/新分类名称
```

创建 `docs/新分类名称/_category_.json`：

```json
{
  "label": "分类显示名称",
  "position": 2,
  "link": {
    "type": "generated-index",
    "description": "分类描述"
  }
}
```

#### 创建文档

在分类目录下创建 `.md` 文件：

```markdown
---
sidebar_position: 1
title: 文档标题
---

# 文档标题

文档内容...
```

### 3. 写博客

在 `blog/` 目录创建文件，命名格式：`YYYY-MM-DD-标题.md`

```markdown
---
slug: url-slug
title: 文章标题
authors: [lizisec]
tags: [标签1, 标签2]
---

这里是摘要，会显示在列表页

<!-- truncate -->

这里是正文内容
```

### 4. 发布更新

```bash
git add .
git commit -m "添加新笔记"
git push
```

等待 1-2 分钟，GitHub Actions 会自动部署。

## Markdown 技巧

### 代码高亮

\`\`\`python
def hello():
    print("Hello, World!")
\`\`\`

### 提示框

```markdown
:::tip 提示
有用的提示信息
:::

:::info 信息
一般信息
:::

:::warning 警告
需要注意的内容
:::

:::danger 危险
重要警告
:::
```

### 标签页

```markdown
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="js" label="JavaScript">
    \`\`\`js
    console.log('Hello');
    \`\`\`
  </TabItem>
  <TabItem value="py" label="Python">
    \`\`\`python
    print('Hello')
    \`\`\`
  </TabItem>
</Tabs>
```

### 折叠内容

```markdown
<details>
  <summary>点击展开</summary>
  
  隐藏的内容
</details>
```

## 常用命令

```bash
# 清理缓存
npm run clear

# 类型检查
npm run typecheck

# 构建
npm run build

# 预览构建结果
npm run serve
```

## 目录结构

```
.
├── blog/                   # 博客文章
│   ├── authors.yml        # 作者信息
│   ├── tags.yml           # 标签定义
│   └── *.md               # 博客文章
├── docs/                   # 文档
│   ├── intro.md           # 首页
│   └── */                 # 分类目录
├── src/                    # 源代码
│   ├── components/        # React 组件
│   ├── css/              # 样式文件
│   └── pages/            # 自定义页面
├── static/                 # 静态资源
│   └── img/              # 图片
├── docusaurus.config.ts   # 配置文件
└── sidebars.ts            # 侧边栏配置
```

## 自定义配置

编辑 `docusaurus.config.ts` 可以修改：

- 站点标题和描述
- 导航栏
- 页脚
- 主题颜色
- 代码高亮语言
- 等等...

详见 [Docusaurus 配置文档](https://docusaurus.io/docs/configuration)

## 问题排查

### 构建失败

1. 检查 GitHub Actions 日志
2. 本地运行 `npm run build` 查看错误
3. 确保所有链接正确

### 样式问题

1. 清理缓存：`npm run clear`
2. 重启开发服务器

### 部署延迟

- GitHub Actions 通常需要 1-2 分钟
- 查看 Actions 标签页确认状态
