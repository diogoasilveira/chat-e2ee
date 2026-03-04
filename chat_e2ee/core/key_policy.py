"""
Module for PGP Key Validation Policy.

Defines rules to validate keys before using them for encryption
or signature verification in E2EE chat.

Policies verified:
  - Key expiration
  - Key revocation
  - Minimum trust level
  - Maximum allowed key age
"""

import time

SECONDS_PER_DAY = 86400
TRUST_LEVELS = {
    "expired": -1,
    "undefined": 0,
    "never":     0,
    "unknown":   0,
    "marginal":  1,
    "full":      2,
    "ultimate":  3,
}
DEFAULT_POLICY = {
    "min_trust": "marginal",
    "max_key_age_days": 365,
    "allow_keys_without_expiration": True,
    "reject_revoked_keys": True,
    "reject_expired_keys": True,
}


class ValidationResult:
    """
    Result of a key validation.
    """

    def __init__(self,
                 valid,
                 reason=""):
        self.valid = valid
        self.reason = reason

    def __bool__(self):
        return self.valid

    def __repr__(self):
        estado = "VALID" if self.valid else "INVALID"
        return f"ValidationResult({estado}, reason='{self.reason}')"


def _trust_value(nivel):
    """
    Returns the numeric value of a trust level.
    """
    if isinstance(nivel, str):
        return TRUST_LEVELS.get(nivel.lower(), -1)
    return -1


def validate_key(key_info,
                policy=None):
    """
    Validates a PGP key according to the configured policy.

    Parameters
    ----------
    key_info : dict
        Dictionary with key information (as returned by gpg.list_keys()).
        Expected fields: 'trust', 'expires', 'date', 'fingerprint', 'uids'.
    policy : dict, optional
        Dictionary with policy rules. If not provided, uses DEFAULT_POLICY.

    Returns
    -------
    ValidationResult
        Object indicating if the key is valid and the reason in case of rejection.
    """
    if policy is None:
        policy = DEFAULT_POLICY

    fingerprint = key_info.get("fingerprint", "unknown")

    if policy.get("reject_revoked_keys", True):
        trust = key_info.get("trust", "")
        if trust == "r":
            return ValidationResult(
                False,
                f"Key {fingerprint} has been revoked."
            )

    if policy.get("reject_expired_keys", True):
        expires = key_info.get("expires", "")
        if expires:
            try:
                expiration_ts = int(expires)
                if expiration_ts > 0 and expiration_ts < time.time():
                    return ValidationResult(
                        False,
                        f"Key {fingerprint} has expired."
                    )
            except (ValueError, TypeError):
                pass

    if not policy.get("allow_keys_without_expiration", True):
        expires = key_info.get("expires", "")
        if not expires:
            return ValidationResult(
                False,
                f"Key {fingerprint} does not have an expiration date and policy requires one."
            )

    min_trust = policy.get("min_trust", "marginal")
    ownertrust = key_info.get("ownertrust", "")
    if ownertrust:
        key_value = _trust_value(ownertrust)
        min_value = _trust_value(min_trust)
        if key_value < min_value:
            return ValidationResult(
                False,
                f"Key {fingerprint} has trust level '{ownertrust}' "
                f"below the minimum required '{min_trust}'."
            )

    max_days = policy.get("max_key_age_days", 0)
    if max_days > 0:
        creation_date = key_info.get("date", "")
        if creation_date:
            try:
                creation_ts = int(creation_date)
                age_seconds = time.time() - creation_ts
                age_days = age_seconds / SECONDS_PER_DAY
                if age_days > max_days:
                    return ValidationResult(
                        False,
                        f"Key {fingerprint} is {int(age_days)} days old, "
                        f"exceeding the maximum of {max_days} days."
                    )
            except (ValueError, TypeError):
                pass

    return ValidationResult(True, "Key approved by policy.")


def search_key_by_uid(gpg,
                      uid):
    """
    Searches for a public key in the keyring by UID (username or email).

    Returns the first key that contains the UID in the 'uids' field, or None.
    """
    keys = gpg.list_keys()
    for key in keys:
        for u in key.get("uids", []):
            if uid.lower() in u.lower():
                return key
    return None


def validate_destination(gpg,
                         destination,
                         policy=None):
    """
    Validates the public key of a recipient before sending a message.

    Parameters
    ----------
    gpg : gnupg.GPG
        GPG instance.
    destination : str
        Username or email of the recipient.
    policy : dict, optional
        Validation policy to be used.

    Returns
    -------
    ValidationResult
        Validation result.
    """
    key = search_key_by_uid(gpg, destination)
    if key is None:
        return ValidationResult(
            False,
            f"Public key of recipient '{destination}' not found in keyring."
        )
    return validate_key(key, policy)


def validate_origin(gpg,
                    origin,
                    policy=None):
    """
    Validates the private key of the sender before signing a message.

    Parameters
    ----------
    gpg : gnupg.GPG
        GPG instance.
    origin : str
        Username or email of the sender.
    policy : dict, optional
        Validation policy to be used.

    Returns
    -------
    ValidationResult
        Validation result.
    """
    keys = gpg.list_keys(True)
    for key in keys:
        for u in key.get("uids", []):
            if origin.lower() in u.lower():
                return validate_key(key, policy)
    return ValidationResult(
        False,
        f"Private key of sender '{origin}' not found in keyring."
    )
