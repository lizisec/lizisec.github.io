#!/usr/bin/env python3
"""Check generated pages without requesting external/lab URLs (stdlib only)."""
import argparse
from collections import Counter
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urljoin, urlsplit
import xml.etree.ElementTree as ET


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.duplicates = set()
        self.refs = []
        self.images = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            if attrs['id'] in self.ids:
                self.duplicates.add(attrs['id'])
            self.ids.add(attrs['id'])
        if tag == 'img':
            self.images += 1
        for name in ('src', 'href', 'poster', 'data-search-index'):
            if name in attrs and attrs[name]:
                self.refs.append((tag, name, attrs[name]))
        if attrs.get('srcset'):
            self.refs.extend((tag, 'srcset', src.strip().split()[0])
                             for src in attrs['srcset'].split(',') if src.strip())


def check(root, baseurl='', origin='https://lizisec.github.io'):
    root = Path(root).resolve()
    baseurl = '/' + baseurl.strip('/') if baseurl.strip('/') else ''
    pages = {file: Page(file.read_text(encoding='utf-8')) for file in root.rglob('*.html')}
    errors = []
    external = set()
    checked = 0

    def resolve(source, ref, check_fragment=True):
        nonlocal checked
        source_url = origin + baseurl + '/' + source.relative_to(root).as_posix()
        if source_url.endswith('/index.html'):
            source_url = source_url[:-len('index.html')]
        url = urlsplit(urljoin(source_url, ref))
        if url.scheme not in ('http', 'https'):
            if url.scheme in ('file', 'obsidian'):
                errors.append(f'{source.relative_to(root)}: local-only URL {ref}')
            return
        if url.netloc != urlsplit(origin).netloc:
            external.add(url.geturl())
            return
        path = unquote(url.path)
        if baseurl:
            if path != baseurl and not path.startswith(baseurl + '/'):
                errors.append(f'{source.relative_to(root)}: link escapes baseurl: {ref}')
                return
            path = path[len(baseurl):]
        target = (root / path.lstrip('/')).resolve()
        if not target.is_relative_to(root):
            errors.append(f'{source.relative_to(root)}: path escapes site: {ref}')
            return
        if target.is_dir():
            target /= 'index.html'
        checked += 1
        if not target.is_file():
            errors.append(f'{source.relative_to(root)}: missing target: {ref}')
        elif check_fragment and url.fragment and target in pages:
            fragment = unquote(url.fragment)
            if not fragment.startswith(':~:text=') and fragment not in pages[target].ids:
                errors.append(f'{source.relative_to(root)}: missing anchor: {ref}')

    for source, page in pages.items():
        for duplicate in sorted(page.duplicates):
            errors.append(f'{source.relative_to(root)}: duplicate id: {duplicate}')
        for tag, name, ref in page.refs:
            resolve(source, ref, check_fragment=(tag == 'a' and name == 'href'))
    for required in ['index.html', 'notes/index.html', 'search/index.html', 'tags/index.html', '404.html']:
        if not (root / required).is_file():
            errors.append(f'missing page: {required}')
    index_path = root / 'search.json'
    try:
        entries = json.loads(index_path.read_text(encoding='utf-8'))
        if not isinstance(entries, list) or not entries:
            raise ValueError('search index must be a non-empty array')
        urls = Counter(entry['url'] for entry in entries)
        for url, count in urls.items():
            if count > 1:
                errors.append(f'search index: duplicate URL: {url}')
        for entry in entries:
            if not entry.get('title') or not isinstance(entry.get('text'), str) or not entry['text'].strip():
                errors.append(f'search index: empty title/text: {entry.get("url")}')
            resolve(index_path, entry['url'])
        expected_notes = len(list((root / 'notes').glob('*/index.html')))
        indexed_notes = sum(entry.get('type') == 'note' for entry in entries)
        if indexed_notes != expected_notes:
            errors.append(f'search index: {indexed_notes} notes for {expected_notes} note pages')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f'invalid search index: {exc}')
    try:
        ET.parse(root / 'feed.xml')
    except (OSError, ET.ParseError) as exc:
        errors.append(f'invalid RSS feed: {exc}')
    for private in ['scripts', 'tests', 'node_modules', 'vendor', 'package.json', 'package-lock.json', 'Gemfile', 'Gemfile.lock']:
        if (root / private).exists():
            errors.append(f'development file published: {private}')
    print(f'Checked {len(pages)} HTML pages, {checked} local references, '
          f'{sum(page.images for page in pages.values())} image elements.')
    print(f'{len(external)} unique external URLs not requested (includes lab/documentation links).')
    for error in errors:
        print('ERROR:', error, file=sys.stderr)
    print(f'{len(errors)} error(s).')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', nargs='?', default='_site')
    parser.add_argument('--baseurl', default='')
    parser.add_argument('--origin', default='https://lizisec.github.io')
    args = parser.parse_args()
    sys.exit(bool(check(args.site, args.baseurl, args.origin)))
