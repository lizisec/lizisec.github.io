# 笔记转换说明

## 已完成的转换

✅ 已将 30 个 Obsidian 格式的靶机笔记转换为 Docusaurus 格式

### 转换内容

1. **图片引用格式转换**
   - Obsidian 格式：`![[Pasted image 20241111150144.png]]`
   - Docusaurus 格式：`![](./Pasted image 20241111150144.png)` 或 `![](./image/Pasted image 20241111150144.png)`

2. **文件组织**
   - 源目录：`靶机walkthrough/`
   - 目标目录：`docs/靶机笔记/`
   - 每个靶机一个子目录，包含 markdown 文件和相关图片

3. **添加 Frontmatter**
   - 为每个笔记添加了标题元数据
   - 便于 Docusaurus 生成导航和索引

### 转换统计

- 总笔记数：30 个
- 总图片数：约 386 张
- 包含平台：
  - HackTheBox (HTB)
  - VulnHub
  - 难度：Easy, Medium, Hard
  - 类型：Windows, Linux, Domain

### 笔记列表

#### Windows 靶机
- Active (HTB-windows-easy-domain)
- Acute (HTB-windows-hard)
- Bastard (HTB-windows-medium)
- blackfield (HTB-windows-hard-domain)
- Cascade (HTB-windows-medium-domain)
- Crafty (HTB-windows-easy)
- Driver (HTB-windows-easy)
- Forest (HTB-windows-easy-domain)
- Json (HTB-windows-medium)
- Mantis (HTB-windows-hard-domain) - 未完成
- Object (HTB-windows-hard-domain)
- pov (HTB-windows-medium)
- Reel (HTB-windows-hard-domain)
- Return (HTB-windows-easy-domain)
- Sauna (HTB-windows-easy-domain)
- Search (HTB-windows-hard-domain)
- ServMon (HTB-windows-easy)
- streamIO (HTB-windows-medium)
- Support (HTB-windows-domain-easy)
- timelapse (HTB-windows-easy)
- Cicada (HTB-windows-easy) - 未完成

#### Linux 靶机
- blurry (HTB-linux-medium)
- Caption (HTB-linux-hard)
- BillyMadison (vulnhub-linux-hard) - 未完成
- Breach2.1 (vulnhub-linux-hard)
- IMF (vulnhub-linux-hard)
- INSANITY (vulnhub-linux-hard)
- Ted (vulnhub-linux-hard)
- WinterMute (vulnhub-linux-hard)

## 使用转换脚本

如果需要重新转换或转换新笔记：

```bash
python3 convert_notes.py
```

脚本会自动：
1. 扫描 `靶机walkthrough/` 目录
2. 转换图片引用格式
3. 复制图片文件
4. 生成 Docusaurus 兼容的文件结构

## 注意事项

1. **图片路径**：图片可以放在笔记同目录或 `image/` 子目录
2. **文件名**：特殊字符会被自动清理（如括号、空格）
3. **编码**：所有文件使用 UTF-8 编码
4. **未完成笔记**：标记为"没打完"的笔记也已包含

## 后续维护

### 添加新笔记

1. 将新笔记放入 `靶机walkthrough/新靶机名称/` 目录
2. 运行 `python3 convert_notes.py`
3. 提交更改

### 更新现有笔记

直接编辑 `docs/靶机笔记/` 下的文件，使用标准 Markdown 图片语法：

```markdown
![图片描述](./image.png)
```

## 构建和部署

```bash
# 本地预览
npm start

# 构建
npm run build

# 部署
git add .
git commit -m "更新笔记"
git push
```

站点会自动部署到 https://lizisec.github.io
