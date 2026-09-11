import json
import tempfile
import unittest
from pathlib import Path

from botscope.config import Config, Scope
from botscope.discovery import PageParser, websocket_message_schema
from botscope.scanner import Scanner


class AdvancedDiscoveryTests(unittest.TestCase):
    def test_spa_hash_routes_and_data_routes_are_retained(self):
        parser = PageParser("https://shop.example.test/")
        parser.feed('<a href="/#/contact">Contact</a><button data-route="/#/account">Account</button><a href="/plain">Plain</a>')
        parser.close()
        self.assertIn("/#/contact", parser.spa_routes)
        self.assertIn("/#/account", parser.spa_routes)

    def test_websocket_schema_redacts_values(self):
        schema = websocket_message_schema('{"token":"SECRET", "items":[{"id":7}], "ok":true}')
        rendered = json.dumps(schema)
        self.assertNotIn("SECRET", rendered)
        self.assertEqual(schema["kind"], "json")
        self.assertEqual(schema["shape"]["token"], "string")

    def test_form_testing_requires_private_scope_and_allowlist(self):
        with self.assertRaises(ValueError):
            Config(target="https://shop.example.test", form_testing=True, form_allowlist=["/search"])
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "paths.txt"
            wordlist.write_text("/admin\n/catalog\n")
            config = Config(target="https://shop.example.test", allow_private=True,
                            form_testing=True, form_allowlist=["/search"],
                            hidden_path_wordlist=str(wordlist))
            self.assertTrue(config.browser)
            scope = Scope(config)
            self.assertTrue(scope.form_allowed("https://shop.example.test/search", "POST"))
            self.assertFalse(scope.form_allowed("https://shop.example.test/login", "POST"))

    def test_hidden_paths_are_bounded_get_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "paths.txt"
            wordlist.write_text("# comment\n/admin\n/catalog\n/private\n")
            scanner = Scanner(Config(target="https://shop.example.test", allow_private=True,
                                     hidden_path_wordlist=str(wordlist), max_hidden_paths=2))
            scanner.load_hidden_paths()
            hidden = [e for e in scanner.inventory.endpoints.values() if "hidden_path" in e.sources]
            self.assertEqual(len(hidden), 2)
            self.assertTrue(all(e.method == "GET" for e in hidden))
            self.assertEqual(scanner.hidden_paths_enqueued, 2)

    def test_hash_seed_is_rendered_candidate(self):
        scanner = Scanner(Config(target="https://shop.example.test", allow_private=True, browser=True))
        scanner.enqueue("https://shop.example.test/#/contact", "seed")
        self.assertIn("https://shop.example.test/#/contact", scanner.browser_candidates)


if __name__ == "__main__":
    unittest.main()
