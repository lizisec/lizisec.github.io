# lizisec notes

使用 Jekyll 构建的个人笔记站点，包含 Hack The Box / VulnHub 靶机复盘与协议利用笔记。

在线访问：[lizisec.github.io](https://lizisec.github.io)

## 本地运行

推荐 **Ruby 3.3.x**（与现有 Pages 构建镜像的 Ruby 系列一致）、Bundler 2.6.6。Gemfile 明确限制 Ruby `< 4.0`，避免解析到不兼容的旧依赖；不要使用 macOS 自带的 Ruby 2.6。Node.js 22 和 Python 3.9+ 仅用于开发检查，不参与线上运行。

```bash
ruby -v
gem install bundler -v 2.6.6
bundle config set --local path vendor/bundle
bundle install
bundle exec jekyll serve --host 127.0.0.1
```

访问 `http://127.0.0.1:4000`。中文目录发生编码错误时，先设置 `LANG=en_US.UTF-8` 和 `LC_ALL=en_US.UTF-8`。依赖安装遇到网络问题时检查网络或使用可信镜像，不要关闭 TLS 校验；本地镜像配置保留在忽略的 `.bundle/`，不要提交。

## 功能

- 首页提供技术文章、靶机入口及自动统计。
- 笔记页支持名称、平台、系统、难度、方向、状态组合筛选，并将条件同步到网址。
- 全文搜索涵盖所有文章和笔记；空格分隔的关键词按 AND 匹配（不区分大小写），匹配范围包括标题、元数据、标签和**完整正文**。标题、元数据命中的结果优先显示。精准的平台/难度筛选请使用笔记页，而不是全文搜索。
- 分类页按文章标签及靶机维度提供索引。
- 文章目录包含 h1–h4；桌面侧栏定位、移动端默认折叠。代码块可横向滚动和复制，图片可通过键盘或点击放大。
- 界面采用 16-bit 赛博终端风格：自托管 NES.css 像素组件与 ZLabs Pixel 中文像素字体，仅标题和控件使用像素字体；正文保持易读字体。移动端保留缩小的像素伙伴。
- JavaScript 不可用时仍可浏览全部笔记、分类和正文；全文搜索与交互筛选需要 JavaScript。

## 内容结构

- `_posts/`：技术文章，文件名使用 `YYYY-MM-DD-slug.md`。
- `notes/`：每篇靶机笔记一个目录，含 `index.md` 和本地图片。
- `_layouts/`、`_includes/`：布局与共用目录/卡片模板。
- `assets/`：样式、前端逻辑、像素伙伴资源，以及自托管的 NES.css 与 ZLabs Pixel 字体。第三方授权文本分别位于 `assets/lib/nes/LICENSE`（MIT）和 `assets/fonts/zlabs-pixel-12px/LICENSE-OFL`（OFL 1.1）；页面不依赖外部 CDN。
- `notes.html` / `tags.html` / `search.html`：笔记、分类、搜索入口。
- `search.json`：Jekyll 生成的完整搜索索引，不需手工更新。
- `404.html`：错误页面，提供返回首页与搜索入口。
- `scripts/`、`tests/`：开发检查，已从部署产物排除。

### 新增靶机笔记

```yaml
---
title: 机器名称
platform: HTB
os: Windows
difficulty: Easy
track: Domain
status: WIP
---
```

- `platform`：如 `HTB` / `VulnHub`。
- `os`：如 `Windows` / `Linux`。
- `difficulty`：`Easy` / `Medium` / `Hard` / `Insane`；未知用 `Unknown`。
- `track`：`Domain` / `Standalone`。
- `status`：可选。未完成可标记 `WIP`，缺失时筛选项显示“未标注”，不会推断为已完成。
- 文章标签可使用 `tags: [协议-SSH, 漏洞-CVE-xxxx-xxxx]`；仅填写实际适用的标签。
- 图片使用同目录相对路径 `![图片说明](screenshot.png)`，文件名大小写必须一致，不要使用本机绝对路径。
- 不随意重命名已有笔记目录或文章 permalink，避免破坏历史链接。
- 新增索引默认收录 `notes/` 下名为 `index.md` 的页面。发布前删除不应公开的凭据及个人信息。

## 发布前检查

```bash
bundle exec jekyll build
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/check_site.py _site
npm ci --ignore-scripts
npm run check:js
npm test
```

链接检查覆盖站内页面、锚点、图片与静态资源、搜索索引、RSS，以及不应发布的开发文件。**不访问外部网址或笔记中的靶机地址**；外部链接需单独确认。前端测试使用 jsdom，不代替真实浏览器视觉检查。

子路径部署验证（可选）：

```bash
bundle exec jekyll build --baseurl /blog --destination /tmp/lizisec-site-subpath
python3 scripts/check_site.py /tmp/lizisec-site-subpath --baseurl /blog
# 恢复本地默认构建
bundle exec jekyll build
```

## 部署

现有 GitHub Actions 工作流保留 Jekyll Pages 构建方式，新增发布前校验：

- PR 指向 `main`：只构建并运行检查，不部署。
- 推送到 `main` 或在 `main` 手动触发：所有检查成功后上传产物、部署。
- 功能分支上手动触发：检查但不部署。
- 写入 Pages 的权限仅授予部署 job；构建 job 只有读取权限。

仓库 Settings → Pages 的发布来源应设置为 **GitHub Actions**。若仓库仍启用旧的分支发布流程，需要仓库拥有者核对设置，避免双重部署。工作流在 `main` 推送后自动检查并部署；本地构建成功不代表远端部署已成功。
