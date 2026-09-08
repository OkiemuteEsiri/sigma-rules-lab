from pathlib import Path
import unittest


RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
REQUIRED_KEYS = (
    "title:",
    "id:",
    "status:",
    "description:",
    "logsource:",
    "detection:",
    "condition:",
    "falsepositives:",
    "level:",
    "tags:",
)


class SigmaMetadataTests(unittest.TestCase):
    def test_rules_exist(self):
        rules = list(RULES_DIR.glob("*.yml"))
        self.assertGreaterEqual(len(rules), 3)

    def test_required_metadata_present(self):
        for rule_path in RULES_DIR.glob("*.yml"):
            content = rule_path.read_text(encoding="utf-8")
            with self.subTest(rule=rule_path.name):
                for key in REQUIRED_KEYS:
                    self.assertIn(key, content, f"{key} missing from {rule_path.name}")

    def test_attack_tag_present(self):
        for rule_path in RULES_DIR.glob("*.yml"):
            content = rule_path.read_text(encoding="utf-8").lower()
            with self.subTest(rule=rule_path.name):
                self.assertIn("attack.t", content)

    def test_no_placeholder_credentials(self):
        forbidden = ("password=", "api_key=", "secret_key=", "bearer ")
        for rule_path in RULES_DIR.glob("*.yml"):
            content = rule_path.read_text(encoding="utf-8").lower()
            with self.subTest(rule=rule_path.name):
                for token in forbidden:
                    self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
