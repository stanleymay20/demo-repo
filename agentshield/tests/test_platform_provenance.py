import unittest

from agentshield.platform.provenance import InputProvenance, TrustLevel


class ProvenanceTests(unittest.TestCase):
    def test_invalid_provenance_cannot_enter_the_evaluation_record(self):
        for kwargs in ({"trust_level": "trusted"}, {"source_id": []}, {"content_type": 1}, {"source_type": 7}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                InputProvenance(**dict({"source_type": "web"}, **kwargs))

    def test_untrusted_requires_screening(self):
        item = InputProvenance(source_type="web", trust_level=TrustLevel.UNTRUSTED)
        self.assertTrue(item.requires_security_screening)

    def test_unknown_requires_screening(self):
        item = InputProvenance(source_type="retrieval", trust_level=TrustLevel.UNKNOWN)
        self.assertTrue(item.requires_security_screening)

    def test_trusted_does_not_require_screening(self):
        item = InputProvenance(source_type="internal", trust_level=TrustLevel.TRUSTED)
        self.assertFalse(item.requires_security_screening)


if __name__ == "__main__":
    unittest.main()
