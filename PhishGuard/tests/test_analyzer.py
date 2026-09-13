import unittest

from analyzer import analyze_message


class AnalyzerTests(unittest.TestCase):
    def test_phishing_sample_is_high_risk(self):
        report = analyze_message(
            "security@paypa1-support.xyz",
            "URGENT!!! Account suspended",
            "Dear Customer, verify your account immediately at http://192.168.1.2/login and confirm your password.",
        )
        self.assertEqual(report["level"], "High")
        self.assertGreaterEqual(len(report["flags"]), 4)

    def test_normal_message_is_low_risk(self):
        report = analyze_message("lecturer@university.edu", "Class update", "Tomorrow's class begins at 10 AM in room A4.")
        self.assertEqual(report["level"], "Low")

    def test_shortened_url_is_detected(self):
        report = analyze_message("", "", "Review this page: https://bit.ly/example")
        categories = [flag["category"] for flag in report["flags"]]
        self.assertIn("Shortened URL", categories)

    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message("", "", "  ")


if __name__ == "__main__":
    unittest.main()
