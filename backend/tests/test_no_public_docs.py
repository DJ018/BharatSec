"""The auto-generated API documentation pages are switched off and not linked from the site."""
import unittest
from pathlib import Path

from tests.auth_helpers import authenticated_client

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


class NoPublicDocsTests(unittest.TestCase):
    def test_docs_pages_do_not_exist_even_when_signed_in(self):
        client = authenticated_client()
        try:
            for path in ("/api/docs", "/api/redoc", "/openapi.json"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 404)
        finally:
            client.close()

    def test_no_page_links_to_api_docs(self):
        for page in FRONTEND.glob("*.html"):
            with self.subTest(page=page.name):
                text = page.read_text(encoding="utf-8")
                self.assertNotIn("/api/docs", text)
                self.assertNotIn("API docs", text)


if __name__ == "__main__":
    unittest.main()
