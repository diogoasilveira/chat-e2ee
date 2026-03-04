"""
Unit tests for the key_policy module (Key Validation Policy).
"""

import time
import unittest

from chat_e2ee.core.key_policy import (
    DEFAULT_POLICY,
    SECONDS_PER_DAY,
    ValidationResult,
    _trust_value,
    search_key_by_uid,
    validate_key,
)


class TestValidationResult(unittest.TestCase):
    """
    Tests for the ValidationResult class.
    """

    def test_valid_result(self):
        r = ValidationResult(True, "ok")
        self.assertTrue(r.valid)
        self.assertTrue(bool(r))
        self.assertIn("VALID", repr(r))

    def test_invalid_result(self):
        r = ValidationResult(False, "expired")
        self.assertFalse(r.valid)
        self.assertFalse(bool(r))
        self.assertIn("INVALID", repr(r))


class TestTrustValue(unittest.TestCase):
    """
    Tests for trust level conversion.
    """

    def test_known_levels(self):
        self.assertEqual(_trust_value("ultimate"), 3)
        self.assertEqual(_trust_value("full"), 2)
        self.assertEqual(_trust_value("marginal"), 1)
        self.assertEqual(_trust_value("undefined"), 0)
        self.assertEqual(_trust_value("expired"), -1)

    def test_unknown_level(self):
        self.assertEqual(_trust_value("invalid"), -1)

    def test_case_insensitive(self):
        self.assertEqual(_trust_value("ULTIMATE"), 3)
        self.assertEqual(_trust_value("Full"), 2)

    def test_invalid_type(self):
        self.assertEqual(_trust_value(123), -1)
        self.assertEqual(_trust_value(None), -1)


class TestValidateKey(unittest.TestCase):
    """
    Tests for the validate_key function.
    """

    def _valid_key(self, **overrides):
        """
        Creates a dictionary with a valid key and default values.
        """
        key = {
            "fingerprint": "ABCD1234",
            "trust": "f",
            "ownertrust": "full",
            "expires": str(int(time.time()) + SECONDS_PER_DAY * 30),
            "date": str(int(time.time()) - SECONDS_PER_DAY * 10),
            "uids": ["alice <alice@example.com>"],
        }
        key.update(overrides)
        return key

    def test_valid_key_approved(self):
        result = validate_key(self._valid_key())
        self.assertTrue(result)
        self.assertIn("approved", result.reason)

    def test_revoked_key_rejected(self):
        key = self._valid_key(trust="r")
        result = validate_key(key)
        self.assertFalse(result)
        self.assertIn("revoked", result.reason)

    def test_revoked_key_allowed_if_policy_disabled(self):
        key = self._valid_key(trust="r")
        policy = {**DEFAULT_POLICY, "reject_revoked_keys": False}
        result = validate_key(key, policy)
        self.assertTrue(result)

    def test_expired_key_rejected(self):
        key = self._valid_key(expires=str(int(time.time()) - SECONDS_PER_DAY))
        result = validate_key(key)
        self.assertFalse(result)
        self.assertIn("expired", result.reason)

    def test_expired_key_allowed_if_policy_disabled(self):
        key = self._valid_key(expires=str(int(time.time()) - SECONDS_PER_DAY))
        policy = {**DEFAULT_POLICY, "reject_expired_keys": False}
        result = validate_key(key, policy)
        self.assertTrue(result)

    def test_key_without_expiration_allowed_by_default(self):
        key = self._valid_key(expires="")
        result = validate_key(key)
        self.assertTrue(result)

    def test_key_without_expiration_rejected_if_policy_requires_it(self):
        key = self._valid_key(expires="")
        policy = {**DEFAULT_POLICY, "allow_keys_without_expiration": False}
        result = validate_key(key, policy)
        self.assertFalse(result)
        self.assertIn("expiration", result.reason)

    def test_insufficient_trust_rejected(self):
        key = self._valid_key(ownertrust="undefined")
        policy = {**DEFAULT_POLICY, "min_trust": "marginal"}
        result = validate_key(key, policy)
        self.assertFalse(result)
        self.assertIn("trust", result.reason)

    def test_sufficient_trust_approved(self):
        key = self._valid_key(ownertrust="full")
        policy = {**DEFAULT_POLICY, "min_trust": "marginal"}
        result = validate_key(key, policy)
        self.assertTrue(result)

    def test_very_old_key_rejected(self):
        key = self._valid_key(
            date=str(int(time.time()) - SECONDS_PER_DAY * 400))
        policy = {**DEFAULT_POLICY, "max_key_age_days": 365}
        result = validate_key(key, policy)
        self.assertFalse(result)
        self.assertIn("exceeding", result.reason)

    def test_recent_key_approved(self):
        key = self._valid_key(
            date=str(int(time.time()) - SECONDS_PER_DAY * 10))
        policy = {**DEFAULT_POLICY, "max_key_age_days": 365}
        result = validate_key(key, policy)
        self.assertTrue(result)

    def test_age_without_limit(self):
        key = self._valid_key(
            date=str(int(time.time()) - SECONDS_PER_DAY * 9999))
        policy = {**DEFAULT_POLICY, "max_key_age_days": 0}
        result = validate_key(key, policy)
        self.assertTrue(result)


class TestSearchKeyByUid(unittest.TestCase):
    """
    Tests for search_key_by_uid with mocked GPG.
    """

    def test_key_found(self):
        class FakeGPG:
            def list_keys(self):
                return [
                    {"uids": ["bob <bob@example.com>"], "fingerprint": "B0B"},
                    {"uids": ["alice <alice@example.com>"],
                        "fingerprint": "A11CE"},
                ]

        key = search_key_by_uid(FakeGPG(), "alice")
        self.assertIsNotNone(key)
        self.assertEqual(key["fingerprint"], "A11CE")

    def test_key_not_found(self):
        class FakeGPG:
            def list_keys(self):
                return [{"uids": ["bob <bob@example.com>"], "fingerprint": "B0B"}]

        key = search_key_by_uid(FakeGPG(), "charlie")
        self.assertIsNone(key)

    def test_case_insensitive_search(self):
        class FakeGPG:
            def list_keys(self):
                return [{"uids": ["Alice <alice@example.com>"], "fingerprint": "A11CE"}]

        key = search_key_by_uid(FakeGPG(), "ALICE")
        self.assertIsNotNone(key)


if __name__ == "__main__":
    unittest.main()
