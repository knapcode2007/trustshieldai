import os
import unittest
from unittest.mock import patch

from backend.app.core.config import Settings, parse_cors_origins_value, get_default_cors_origins


class CorsConfigTestCase(unittest.TestCase):
    """Regression tests for CORS_ORIGINS parsing, Pydantic settings, and production safety."""

    def test_parse_cors_origins_value_direct(self):
        """Tests parse_cors_origins_value utility against various raw input formats."""
        # Comma-separated string (Render format)
        res = parse_cors_origins_value("https://trustshield.vercel.app,http://localhost:5173,http://localhost:3000")
        self.assertEqual(res, ["https://trustshield.vercel.app", "http://localhost:5173", "http://localhost:3000"])

        # JSON array string
        res = parse_cors_origins_value('["https://app.vercel.app", "https://admin.vercel.app"]')
        self.assertEqual(res, ["https://app.vercel.app", "https://admin.vercel.app"])

        # Trailing slashes and irregular whitespace
        res = parse_cors_origins_value("  https://trustshield.vercel.app/ ,   http://localhost:5173/  ")
        self.assertEqual(res, ["https://trustshield.vercel.app", "http://localhost:5173"])

        # Malformed bracket notation
        res = parse_cors_origins_value("[https://app.vercel.app, http://localhost:5173]")
        self.assertEqual(res, ["https://app.vercel.app", "http://localhost:5173"])

        # Direct list
        res = parse_cors_origins_value(["https://a.com/", "https://b.com"])
        self.assertEqual(res, ["https://a.com", "https://b.com"])

        # Empty / None
        self.assertEqual(parse_cors_origins_value(""), [])
        self.assertEqual(parse_cors_origins_value(None), [])

    def test_comma_separated_env_var_pydantic_settings(self):
        """Verifies that Pydantic Settings accepts Render-style comma-separated env values."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CORS_ORIGINS": "https://trustshield.vercel.app,http://localhost:5173,http://localhost:3000"
        }, clear=False):
            s = Settings()
            self.assertEqual(
                s.CORS_ORIGINS,
                ["https://trustshield.vercel.app", "http://localhost:5173", "http://localhost:3000"]
            )
            self.assertIsInstance(s.CORS_ORIGINS, list)

    def test_json_array_env_var_pydantic_settings(self):
        """Verifies that Pydantic Settings accepts valid JSON array string env values."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CORS_ORIGINS": '["https://trustshield.vercel.app", "http://localhost:5173"]'
        }, clear=False):
            s = Settings()
            self.assertEqual(
                s.CORS_ORIGINS,
                ["https://trustshield.vercel.app", "http://localhost:5173"]
            )

    def test_wildcard_stripped_in_production(self):
        """Verifies that wildcard '*' is strictly stripped when ENVIRONMENT=production."""
        # Comma-separated with wildcard
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CORS_ORIGINS": "https://trustshield.vercel.app, *"
        }, clear=False):
            s = Settings()
            self.assertEqual(s.CORS_ORIGINS, ["https://trustshield.vercel.app"])
            self.assertNotIn("*", s.CORS_ORIGINS)

        # Sole wildcard in production
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CORS_ORIGINS": "*"
        }, clear=False):
            s = Settings()
            self.assertEqual(s.CORS_ORIGINS, [])
            self.assertNotIn("*", s.CORS_ORIGINS)

        # Default origins in production
        defaults = get_default_cors_origins("production")
        self.assertNotIn("*", defaults)

    def test_wildcard_allowed_in_development(self):
        """Verifies that wildcard '*' is preserved when ENVIRONMENT=development."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "development",
            "CORS_ORIGINS": "http://localhost:5173, *"
        }, clear=False):
            s = Settings()
            self.assertIn("*", s.CORS_ORIGINS)

    def test_malformed_values_do_not_crash_settings(self):
        """Verifies that unexpected or malformed inputs do not crash Settings initialization."""
        malformed_inputs = [
            ",,,",
            "   ",
            "[broken json",
            "https://a.com,,https://b.com",
            "{'not': 'a list'}",
        ]
        for val in malformed_inputs:
            with patch.dict(os.environ, {"CORS_ORIGINS": val, "ENVIRONMENT": "development"}, clear=False):
                s = Settings()
                self.assertIsInstance(s.CORS_ORIGINS, list)

    def test_app_import_with_comma_separated_cors(self):
        """Verifies that FastAPI main:app imports cleanly with Render-supplied CORS_ORIGINS."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CORS_ORIGINS": "https://trustshield.vercel.app,http://localhost:5173,http://localhost:3000"
        }, clear=False):
            from backend.app.main import app
            self.assertIsNotNone(app)


if __name__ == "__main__":
    unittest.main()
