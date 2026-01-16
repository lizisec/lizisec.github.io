import os
import re

TARGET_DIR = "/Users/lizi/Desktop/my-htb-notes/docs/靶机笔记"

def parse_md(path):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    sections = []
    current_section = {"level": 0, "title": "root", "content": [], "subsections": []}
    stack = [current_section]
    
    # We will treat the document as a tree of sections
    # But for simple regex re-organization, a flat list with levels might be easier to reason about 
    # and then reconstruct.
    # actually, let's just classify "blocks" by their headers.
    
    blocks = []
    current_block = {"header_level": 0, "header_text": "root", "lines": []}
    
    for line in lines:
        match = re.match(r'^(#+)\s+(.*)', line)
        if match:
            # Save previous block
            blocks.append(current_block)
            
            level = len(match.group(1))
            text = match.group(2).strip()
            current_block = {"header_level": level, "header_text": text, "lines": [line]}
        else:
            current_block["lines"].append(line)
            
    blocks.append(current_block)
    return blocks

def categorize_block(text):
    text = text.lower()
    if any(x in text for x in ['信息收集', 'information gathering', 'scanning', 'enumeration', '端口扫描', 'nmap', 'discovery']):
        return 'info'
    if any(x in text for x in ['漏洞利用', '初始访问', 'initial access', 'foothold', 'get shell', 'web', 'exploitation', '漏洞']):
        return 'exploit'
    if any(x in text for x in ['权限提升', 'privilege escalation', 'root', 'privesc', '提权']):
        return 'privesc'
    return 'other'

def process_file(path, dry_run=True):
    blocks = parse_md(path)
    
    new_blocks = []
    
    # We want to ensure 3 main containers exist
    info_container = {"header_line": "\n## 信息收集\n", "sub_blocks": []}
    exploit_container = {"header_line": "\n## 漏洞利用\n", "sub_blocks": []}
    privesc_container = {"header_line": "\n## 权限提升\n", "sub_blocks": []}
    
    intro_blocks = []
    
    # Keep track if we have seen the main headers already to avoid duplication
    has_info = False
    has_exploit = False
    has_privesc = False
    
    for block in blocks:
        level = block["header_level"]
        text = block["header_text"]
        
        if level == 0: # Root/Intro
            intro_blocks.append(block)
            continue
            
        category = categorize_block(text)
        
        # Check if it IS a main header
        is_main_info = text == '信息收集' or text == 'Information Gathering'
        is_main_exploit = text == '漏洞利用' or text == 'Initial Access' or text == '初始访问'
        is_main_privesc = text == '权限提升' or text == 'Privilege Escalation'
        
        if is_main_info:
            has_info = True
            # Keep the block content (minus scanner/tools usually), but we will append subs to it
            # actually, usually main headers are empty or just intro text
            info_container["sub_blocks"].append(block) 
            continue
        if is_main_exploit:
            has_exploit = True
            exploit_container["sub_blocks"].append(block)
            continue
        if is_main_privesc:
            has_privesc = True
            privesc_container["sub_blocks"].append(block)
            continue
            
        # If not a main header, decide where it goes
        if category == 'info':
            # Demote if level 2
            if level == 2:
                block["lines"][0] = f"### {text}\n"
            info_container["sub_blocks"].append(block)
        elif category == 'exploit':
            # Demote if level 2
            if level == 2:
                block["lines"][0] = f"### {text}\n"
            exploit_container["sub_blocks"].append(block)
        elif category == 'privesc':
             # Demote if level 2
            if level == 2:
                block["lines"][0] = f"### {text}\n"
            privesc_container["sub_blocks"].append(block)
        else:
            # Default to Info if early logic, or Exploit/Privesc based on position?
            # It is safer to append to the "current" container if possible, but our parsing is block based.
            # If we are unsure, we might leave it or put it in info if it looks like early steps.
            # For now, let's put 'other' top level blocks at the end or keep them as is?
            # Creating a catch-all is risky.
            # If level 2 and unidentified, maybe just leave it as a distinct section.
            intro_blocks.append(block)

    # Construct content
    new_content = []
    
    # Intro
    for b in intro_blocks:
        new_content.extend(b["lines"])
        
    # Info
    new_content.append(info_container["header_line"])
    # Filter out original "Info" header blocks if we added the wrapper, 
    # parse logic above added them to sub_blocks, so we need to be careful not to duplicate headers.
    # Actually, if the user already had "## 信息收集", we added it to sub_blocks.
    # If we print ## 信息收集 again, we duplicate.
    
    # Refined Logic:
    # Just print the sub blocks. If the sub block IS the header, print it.
    # BUT we want to enforce standard naming.
    # So if we have a block that was "## Information Gathering", we might want to drop its header line 
    # and just keep content, because we printed "## 信息收集".
    
    def add_container_content(container, default_title):
        if not container["sub_blocks"]:
            return # Don't add empty sections? Or maybe add them with TODO?
            
        new_content.append(default_title + "\n")
        
        for b in container["sub_blocks"]:
            # Check if this block WAS a main header alias
            t = b["header_text"]
            # If it marks the section start, we skip the header line (since we just printed default_title)
            # EXCEPT if it has content, we print the content.
            is_alias = t in ['信息收集', 'Information Gathering', '漏洞利用', '初始访问', 'Initial Access', '权限提升', 'Privilege Escalation']
            
            if is_alias and b["header_level"] == 2:
                # Skip the header line, keep the rest
                 new_content.extend(b["lines"][1:])
            else:
                 new_content.extend(b["lines"])

    add_container_content(info_container, "## 信息收集")
    add_container_content(exploit_container, "## 漏洞利用")
    add_container_content(privesc_container, "## 权限提升")
    
    # Write back
    final_text = "".join(new_content)
    
    if dry_run:
        print(f"--- Dry Run {path} ---")
        # print(final_text[:500] + "...")
        print("Reorganized.")
    else:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(final_text)
        print(f"Updated {path}")

# Run
import glob
files = glob.glob(os.path.join(TARGET_DIR, "*/*.md"))
print(f"Found {len(files)} files.")

for f in files:
    process_file(f, dry_run=True) # Start with Dry Run
