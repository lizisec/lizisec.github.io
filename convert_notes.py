#!/usr/bin/env python3
"""
将 Obsidian 格式的笔记转换为 Docusaurus 格式
主要处理：
1. 图片引用格式：![[image.png]] -> ![](./image.png) 或 ![](./image/image.png)
2. 移动笔记到 docs 目录
3. 创建分类配置
"""

import os
import re
import shutil
from pathlib import Path

# 源目录和目标目录
SOURCE_DIR = "靶机walkthrough"
TARGET_DIR = "docs/靶机笔记"

def convert_image_references(content, md_file_path):
    """
    转换 Obsidian 图片引用格式为 Markdown 标准格式
    ![[Pasted image 20241111150144.png]] -> ![](./Pasted image 20241111150144.png)
    """
    # 获取 md 文件所在目录
    md_dir = os.path.dirname(md_file_path)
    
    # 匹配 ![[图片名]] 格式
    pattern = r'!\[\[(.*?\.(?:png|jpg|jpeg|gif|webp))\]\]'
    
    def replace_image(match):
        image_name = match.group(1)
        
        # 检查图片是否存在于同目录
        if os.path.exists(os.path.join(md_dir, image_name)):
            return f'![](./{image_name})'
        
        # 检查图片是否在 image 子目录
        if os.path.exists(os.path.join(md_dir, 'image', image_name)):
            return f'![](./image/{image_name})'
        
        # 如果都找不到，保持原样但添加警告注释
        print(f"  ⚠️  警告: 找不到图片 {image_name} 在 {md_dir}")
        return f'![](./{image_name}) <!-- 图片未找到 -->'
    
    converted = re.sub(pattern, replace_image, content, flags=re.IGNORECASE)
    return converted

def create_category_json(category_name, position):
    """创建分类配置文件"""
    return {
        "label": category_name,
        "position": position,
        "link": {
            "type": "generated-index",
            "description": f"{category_name}的渗透测试笔记"
        }
    }

def sanitize_filename(name):
    """清理文件名，移除特殊字符"""
    # 移除或替换不适合做文件名的字符
    name = name.replace('(', '-').replace(')', '')
    name = name.replace(' ', '-')
    return name

def process_notes():
    """处理所有笔记"""
    source_path = Path(SOURCE_DIR)
    target_path = Path(TARGET_DIR)
    
    # 创建目标目录
    target_path.mkdir(parents=True, exist_ok=True)
    
    # 创建主分类配置
    import json
    category_config = {
        "label": "靶机笔记",
        "position": 3,
        "link": {
            "type": "generated-index",
            "description": "HackTheBox 和 VulnHub 靶机的渗透测试笔记"
        }
    }
    
    with open(target_path / '_category_.json', 'w', encoding='utf-8') as f:
        json.dump(category_config, f, ensure_ascii=False, indent=2)
    
    print(f"📁 开始处理笔记...")
    print(f"   源目录: {source_path}")
    print(f"   目标目录: {target_path}\n")
    
    # 遍历所有子目录
    subdirs = [d for d in source_path.iterdir() if d.is_dir()]
    total = len(subdirs)
    
    for idx, subdir in enumerate(subdirs, 1):
        dir_name = subdir.name
        print(f"[{idx}/{total}] 处理: {dir_name}")
        
        # 创建目标子目录
        safe_dir_name = sanitize_filename(dir_name)
        target_subdir = target_path / safe_dir_name
        target_subdir.mkdir(exist_ok=True)
        
        # 查找 .md 文件
        md_files = list(subdir.glob('*.md'))
        
        if not md_files:
            print(f"  ⚠️  未找到 .md 文件")
            continue
        
        # 处理每个 md 文件
        for md_file in md_files:
            print(f"  📝 转换: {md_file.name}")
            
            # 读取内容
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                print(f"  ❌ 编码错误，跳过")
                continue
            
            # 转换图片引用
            converted_content = convert_image_references(content, str(md_file))
            
            # 添加 frontmatter（如果没有）
            if not converted_content.startswith('---'):
                title = dir_name.split('(')[0].strip()
                frontmatter = f"""---
title: {title}
pagination_prev: null
pagination_next: null
---

"""
                converted_content = frontmatter + converted_content
            elif 'pagination_prev' not in converted_content:
                # 如果已有 frontmatter 但没有 pagination 设置，添加它
                lines = converted_content.split('\n')
                if lines[0] == '---':
                    # 找到第二个 ---
                    end_idx = lines[1:].index('---') + 1
                    lines.insert(end_idx, 'pagination_prev: null')
                    lines.insert(end_idx + 1, 'pagination_next: null')
                    converted_content = '\n'.join(lines)
            
            # 写入目标文件
            target_md = target_subdir / md_file.name
            with open(target_md, 'w', encoding='utf-8') as f:
                f.write(converted_content)
        
        # 复制图片文件
        image_count = 0
        
        # 复制同目录下的图片
        for ext in ['*.png', '*.jpg', '*.jpeg', '*.gif', '*.webp']:
            for img in subdir.glob(ext):
                shutil.copy2(img, target_subdir / img.name)
                image_count += 1
        
        # 复制 image 子目录
        image_dir = subdir / 'image'
        if image_dir.exists():
            target_image_dir = target_subdir / 'image'
            target_image_dir.mkdir(exist_ok=True)
            for ext in ['*.png', '*.jpg', '*.jpeg', '*.gif', '*.webp']:
                for img in image_dir.glob(ext):
                    shutil.copy2(img, target_image_dir / img.name)
                    image_count += 1
        
        if image_count > 0:
            print(f"  🖼️  复制了 {image_count} 张图片")
        
        print()
    
    print(f"✅ 完成！共处理 {total} 个笔记目录")
    print(f"📂 笔记已保存到: {target_path}")

if __name__ == '__main__':
    process_notes()
