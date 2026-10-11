import unittest
from datetime import datetime, timezone
from unittest import mock

from defusedxml import EntitiesForbidden

from scripts import feeds
from scripts.common import Fail
from tests.fakes import FakeResponse, FakeSession

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>New</title><link>https://thedfirreport.com/2026/10/01/new/</link><pubDate>Thu, 01 Oct 2026 10:00:00 +0000</pubDate></item>
<item><title>Old</title><link>https://thedfirreport.com/2026/01/01/old/</link><pubDate>Thu, 01 Jan 2026 10:00:00 +0000</pubDate></item>
<item><title>Elsewhere</title><link>https://evil.example/thedfirreport.com</link><pubDate>Thu, 01 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Advisory</title><link rel="alternate" href="https://cyber.gc.ca/en/alerts-advisories/x"/><updated>2026-10-09T12:00:00Z</updated></entry>
</feed>"""

BOMB = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><rss><channel><item><title>&lol2;</title></item></channel></rss>"""


class Parsing(unittest.TestCase):
    def test_rss_and_atom(self):
        self.assertEqual([title for title, _, _ in feeds.parse_feed(RSS)], ["New", "Old", "Elsewhere"])
        [(title, link, when)] = feeds.parse_feed(ATOM)
        self.assertEqual((title, link), ("Advisory", "https://cyber.gc.ca/en/alerts-advisories/x"))
        self.assertEqual(when, datetime(2026, 10, 9, 12, tzinfo=timezone.utc))

    def test_entities_are_refused(self):
        with self.assertRaises(EntitiesForbidden):
            feeds.parse_feed(BOMB)

    def test_feed_items_are_filtered_by_age_and_domain(self):
        config = {"feeds": [{"name": "DFIR", "url": "https://thedfirreport.com/feed/", "domain": "thedfirreport.com"}]}
        session = FakeSession({"thedfirreport.com/feed": FakeResponse(200, RSS, {"Content-Type": "application/xml"})})
        with mock.patch.object(feeds, "load_yaml", return_value=config):
            found = feeds.feed_articles(session, now=datetime(2026, 10, 5, tzinfo=timezone.utc))
        self.assertEqual([a.url for a in found], ["https://thedfirreport.com/2026/10/01/new"])


class Urls(unittest.TestCase):
    def test_on_domain(self):
        self.assertTrue(feeds.on_domain("https://www.microsoft.com/en-us/security/blog/x", "microsoft.com"))
        self.assertFalse(feeds.on_domain("https://microsoft.com.evil.example/x", "microsoft.com"))
        self.assertFalse(feeds.on_domain("http://microsoft.com/x", "microsoft.com"))

    def test_normalize(self):
        self.assertEqual(feeds.normalize("https://Example.com/a/?utm_source=x&id=2#top"), "https://example.com/a?id=2")

    def test_redirects_must_stay_on_the_domain(self):
        session = FakeSession({"redcanary.com/blog/a": FakeResponse(302, b"", {"Location": "https://evil.example/a"})})
        article = feeds.Article("https://redcanary.com/blog/a", "a", domain="redcanary.com")
        with self.assertRaises(Fail):
            feeds.fetch_article(session, article)

    def test_pull_request_sources(self):
        prs = [{"description": "## x\n\nSource: https://redcanary.com/blog/a/?utm_medium=rss\nFrom: Red Canary"},
               {"description": None}]
        self.assertEqual(feeds.urls_in_pull_requests(prs), {"https://redcanary.com/blog/a"})


class Cleaning(unittest.TestCase):
    def test_hidden_content_is_dropped(self):
        html = """<html><head><title>T</title><script>alert(1)</script></head><body>
        <nav>Menu</nav><article><p>Visible behavior: rundll32 launched from Word.</p>
        <p hidden>Hidden instruction one.</p><div style="display: none">Hidden instruction two.</div>
        <span aria-hidden="true">Hidden three.</span><!-- comment instruction --></article></body></html>"""
        title, text = feeds.clean_html(html)
        self.assertEqual(title, "T")
        self.assertIn("Visible behavior", text)
        for hidden in ("Hidden instruction one", "Hidden instruction two", "Hidden three", "comment instruction",
                       "alert(1)", "Menu"):
            self.assertNotIn(hidden, text)


if __name__ == "__main__":
    unittest.main()
