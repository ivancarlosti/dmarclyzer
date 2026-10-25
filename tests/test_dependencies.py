"""Regression tests for the dependency pins in ``requirements.txt``.

Only the standard library is required, so the suite runs before the
third-party dependencies are installed.

``pip-audit --no-deps`` audits exactly what ``requirements.txt`` pins, so
anything that ships in the image has to appear there explicitly — including
the security-critical transitive packages (``pillow`` via streamlit,
``certifi`` via requests). These tests keep that invariant from being lost.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIREMENTS_PATH = os.path.join(REPO_ROOT, "requirements.txt")
SECURITY_WORKFLOW_PATH = os.path.join(
    REPO_ROOT, ".github", "workflows", "security.yml"
)

# An exact ``name==version`` pin only: extras, markers and ranges make the
# version resolved at build time unpredictable and weaken the audit gate.
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)"
    r"==(?P<version>[A-Za-z0-9_.+-]*\d[A-Za-z0-9_.+-]*)$"
)

# Packages whose drift is a critical finding, with the first patched release.
_MINIMUM_VERSIONS = {
    # GHSA-5x8w-8jj5-q52h (FlashPix heap overflow -> code execution) plus 40
    # other advisories affect every release before 13.0.0.
    "pillow": (13, 0, 0),
    # GHSA-6q48-6c7w-9gw2: bundles emSign roots with compromised
    # intermediate CA keys; the first fixed release is 2026.10.19.
    "certifi": (2026, 10, 19),
    # First release that supports pillow 13 (constraint: pillow<14,>=9.2.0).
    "streamlit": (1, 66, 1),
}

# ``streamlit==1.66.1`` requires ``pillow<14``: a newer pillow would make the
# image uninstallable, so the upper bound is asserted as well.
_PILLOW_UPPER_BOUND = (14,)


def _read_pins(path=REQUIREMENTS_PATH):
    """Return ``({lowercase name: version}, [duplicated names])``."""
    pins = {}
    duplicates = []
    with open(path, encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            match = _PIN_RE.match(line)
            if match is None:
                raise AssertionError(
                    f"{path}:{line_number} is not an exact 'name==version' "
                    f"pin: {raw.strip()!r}"
                )
            name = match.group("name").lower()
            if name in pins:
                duplicates.append(name)
            pins[name] = match.group("version")
    return pins, duplicates


def _version_key(version):
    """Turn ``1.2.3`` / ``2026.10.19`` into a comparable tuple of ints."""
    key = []
    for part in re.split(r"[._+-]", version):
        digits = re.match(r"\d+", part)
        if digits is None:
            break
        key.append(int(digits.group()))
    return tuple(key)


class RequirementPinTests(unittest.TestCase):
    def setUp(self):
        self.pins, self.duplicates = _read_pins()

    def test_requirements_file_is_not_empty(self):
        self.assertTrue(self.pins)

    def test_every_requirement_is_an_exact_pin(self):
        # ``_read_pins`` already rejects ranges, extras and markers; reaching
        # here means every line is a plain ``name==version`` pin.
        self.assertEqual(self.duplicates, [])

    def test_security_critical_transitive_packages_are_pinned(self):
        for name in ("pillow", "certifi"):
            with self.subTest(package=name):
                self.assertIn(
                    name,
                    self.pins,
                    f"{name} is a transitive dependency of a pinned package; "
                    "pin it explicitly in requirements.txt so pip-audit "
                    "--no-deps audits it",
                )

    def test_minimum_patched_versions(self):
        for name, minimum in _MINIMUM_VERSIONS.items():
            with self.subTest(package=name):
                self.assertIn(name, self.pins)
                self.assertGreaterEqual(
                    _version_key(self.pins[name]),
                    minimum,
                    f"{name}=={self.pins[name]} is below the patched floor "
                    f"{'.'.join(str(part) for part in minimum)}",
                )

    def test_pillow_stays_inside_the_streamlit_constraint(self):
        self.assertLess(
            _version_key(self.pins["pillow"]),
            _PILLOW_UPPER_BOUND,
            "streamlit 1.66.1 requires pillow<14",
        )


class AuditWorkflowTests(unittest.TestCase):
    def test_ci_audits_the_resolved_dependency_tree(self):
        with open(SECURITY_WORKFLOW_PATH, encoding="utf-8") as handle:
            workflow = handle.read()
        # Without this step only the direct pins are audited and transitive
        # advisories (pillow, certifi) go unnoticed.
        self.assertIn("pip-audit -r requirements.txt --strict", workflow)


if __name__ == "__main__":
    unittest.main()
