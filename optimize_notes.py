#!/usr/bin/env python3
"""
优化 Markdown 笔记格式
主要优化：
1. 统一代码块标记（~~~ -> ```）
2. 规范标题层级（避免跳级）
3. 添加适当的空行
4. 清理多余的空白行
5. 优化列表格式
"""

import os
import re
from pathlib import Path

TARGET_DIR = "docs/靶机笔记"

def optimize_markdown(content):
    """优化 Markdown 内容"""
    
    # 1. 将 ~~~ 替换为 ```（标准 Markdown 代码块）
    content = content.replace('~~~', '```')
    
    # 2. 确保代码块后有语言标识（如果没有的话，添加 bash）
    # 匹配 ``` 后面直接是换行的情况
    def add_language_hint(match):
        # 检查是否是命令行输出（包含 $ 或 # 提示符）
        code_content = match.group(1)
        if re.search(r'^\s*[┌└├─│]', code_content, re.MULTILINE):
            return f'```bash\n{code_content}```'
        elif re.search(r'^\s*[$#]', code_content, re.MULTILINE):
            return f'```bash\n{code_content}```'
        else:
            return match.group(0)
    
    content = re.sub(r'```\n(.*?)```', add_language_hint, content, flags=re.DOTALL)
    
    # 3. 规范标题层级
    # 确保一级标题后是二级标题，不要跳到三级
    lines = content.split('\n')
    optimized_lines = []
    prev_heading_level = 0
    in_frontmatter = False
    
    for i, line in enumerate(lines):
        # 跳过 frontmatter
        if line.strip() == '---':
            in_frontmatter = not in_frontmatter
            optimized_lines.append(line)
            continue
        
        if in_frontmatter:
            optimized_lines.append(line)
            continue
        
        # 检查是否是标题
        heading_match = re.match(r'^(#{1,6})\s+(.+)$', line)
        if heading_match:
            level = len(heading_match.group(1))
            title = heading_match.group(2)
            
            # 如果跳级太多，调整为合理的层级
            if prev_heading_level > 0 and level > prev_heading_level + 1:
                level = prev_heading_level + 1
                line = '#' * level + ' ' + title
            
            prev_heading_level = level
            
            # 确保标题前有空行（除非是文件开头或 frontmatter 后）
            if optimized_lines and optimized_lines[-1].strip() != '' and not optimized_lines[-1].startswith('---'):
                optimized_lines.append('')
            
            optimized_lines.append(line)
            continue
        
        optimized_lines.append(line)
    
    content = '\n'.join(optimized_lines)
    
    # 4. 清理多余的空白行（超过2个连续空行压缩为2个）
    content = re.sub(r'\n{4,}', '\n\n\n', content)
    
    # 5. 确保代码块前后有空行
    content = re.sub(r'([^\n])\n```', r'\1\n\n```', content)
    content = re.sub(r'```\n([^\n])', r'```\n\n\1', content)
    
    # 6. 清理行尾空白
    lines = content.split('\n')
    lines = [line.rstrip() for line in lines]
    content = '\n'.join(lines)
    
    # 7. 确保文件以单个换行符结尾
    content = content.rstrip() + '\n'
    
    return content

def process_notes():
    """处理所有笔记"""
    target_path = Path(TARGET_DIR)
    
    if not target_path.exists():
        print(f"❌ 目录不存在: {target_path}")
        return
    
    print(f"📁 开始优化笔记格式...")
    print(f"   目标目录: {target_path}\n")
    
    # 查找所有 .md 文件
    md_files = list(target_path.rglob('*.md'))
    total = len(md_files)
    
    if total == 0:
        print("⚠️  未找到 Markdown 文件")
        return
    
    optimized_count = 0
    
    for idx, md_file in enumerate(md_files, 1):
        # 跳过 _category_.json 等非笔记文件
        if md_file.name.startswith('_'):
            continue
        
        relative_path = md_file.relative_to(target_path)
        print(f"[{idx}/{total}] 优化: {relative_path}")
        
        try:
            # 读取文件
            with open(md_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # 优化内容
            optimized_content = optimize_markdown(original_content)
            
            # 只有内容改变时才写入
            if optimized_content != original_content:
                with open(md_file, 'w', encoding='utf-8') as f:
                    f.write(optimized_content)
                print(f"  ✅ 已优化")
                optimized_count += 1
            else:
                print(f"  ⏭️  无需优化")
        
        except Exception as e:
            print(f"  ❌ 错误: {e}")
    
    print(f"\n✅ 完成！共优化 {optimized_count}/{total} 个文件")

if __name__ == '__main__':
    process_notes()
