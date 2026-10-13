import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('check_site', Path(__file__).parents[1] / 'scripts/check_site.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class SiteCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for page in ['index.html', 'notes/index.html', 'search/index.html', 'tags/index.html', '404.html']:
            target = self.root / page
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('<h1 id="标题">Title</h1>', encoding='utf-8')
        (self.root / 'search.json').write_text(json.dumps([{'type': 'post', 'title': 'Title', 'url': '/', 'text': 'Body'}]))
        (self.root / 'feed.xml').write_text('<feed/>')

    def check(self, baseurl=''):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return checker.check(self.root, baseurl)

    def test_encoded_anchor_and_relative_image(self):
        (self.root / 'notes/截图.png').write_bytes(b'fixture')
        (self.root / 'notes/index.html').write_text('<a href="../#%E6%A0%87%E9%A2%98">title</a><img src="%E6%88%AA%E5%9B%BE.png">')
        self.assertEqual(self.check(), [])

    def test_broken_asset_and_anchor_are_reported(self):
        (self.root / 'notes/index.html').write_text('<a href="../#missing">missing</a><img src="lost.png">')
        errors = self.check()
        self.assertTrue(any('missing target: lost.png' in error for error in errors))
        self.assertTrue(any('missing anchor' in error for error in errors))

    def test_external_lab_links_are_never_requested(self):
        (self.root / 'notes/index.html').write_text('<a href="http://10.10.10.1/admin">Lab</a><a href="https://example.invalid">External</a>')
        self.assertEqual(self.check(), [])

    def test_baseurl_and_duplicate_ids(self):
        (self.root / 'search.json').write_text(json.dumps([{'type': 'post', 'title': 'Title', 'url': '/blog/', 'text': 'Body'}]))
        (self.root / 'notes/index.html').write_text('<a href="/blog/#标题">Title</a>')
        self.assertEqual(self.check('/blog'), [])
        (self.root / 'notes/index.html').write_text('<h2 id="dup">A</h2><h2 id="dup">B</h2><a href="/">escape</a>')
        errors = self.check('/blog')
        self.assertTrue(any('duplicate id' in error for error in errors))
        self.assertTrue(any('escapes baseurl' in error for error in errors))

    def test_invalid_search_index_and_private_file_fail(self):
        (self.root / 'search.json').write_text('broken')
        (self.root / 'Gemfile').write_text('development only')
        errors = self.check()
        self.assertTrue(any('invalid search index' in error for error in errors))
        self.assertTrue(any('development file published' in error for error in errors))


if __name__ == '__main__':
    unittest.main()
