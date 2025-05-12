# TopSecret is a simple secret management tool that allows users to encrypt and
# decrypt secrets using a passphrase.
# Copyright (C) <2025>  <Emiliano Dalla Verde Marcozzi>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import hashlib
import os
from enum import StrEnum

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from topsecret.domain import Cipherkey, CipherProtocol, Ciphertext, DecryptionError, Metadata, Salt


class PKCS7AESCipher(CipherProtocol):
    class MethodType(StrEnum):
        PASSPHRASE = "passphrase"  # noqa: S105
        AUTO = "auto"

    def __init__(self, iterations: int = 100000, algorithm: hashes.HashAlgorithm | None = None):
        self.iterations = iterations
        self.algorithm = algorithm or hashes.SHA256()

    AUTO_KEY_SEP = b"|"

    def encrypt(self, data: bytes, passphrase: str | None = None) -> tuple[Ciphertext, Metadata]:
        """Encrypts the provided data using either a passphrase or an auto-generated key.

        This method supports two modes of encryption:

        1.  **Passphrase-based**: If a `passphrase` is provided, a key is derived
            from it using PBKDF2HMAC. A salt is generated (or used if provided
            internally, though this implementation always generates a new one for
            passphrase encryption via `_get_key`) and prepended to the ciphertext.
            The metadata will indicate `method: "passphrase"`.

        2.  **Auto-generated key**: If no `passphrase` is provided, a new Fernet key
            is generated. This key is then prepended to the ciphertext, separated
            by a `b"|"` delimiter. The metadata will indicate `method: "auto"`.

        The Fernet symmetric encryption algorithm is used for the actual encryption
        of the data.

        Args:
            data: The bytes to be encrypted.
            passphrase: An optional secret phrase. If provided, it's used to
                derive the encryption key. If None, a new key is generated
                and stored with the ciphertext.

        Returns:
            A tuple containing:
                - Ciphertext: The encrypted data.
                  If passphrase-based, this is `salt + encrypted_content`.
                  If auto-key based, this is `key + b"|" + encrypted_content`.
                - Metadata: A dictionary containing information about the
                  encryption process, specifically the `method` used
                  ("passphrase" or "auto").
        """
        key, salt = _get_key(passphrase, algorithm=self.algorithm, iterations=self.iterations)
        cipher = Fernet(key)
        ciphertext = cipher.encrypt(data)

        metadata: Metadata = {}
        if passphrase:
            # For passphrase-based encryption, salt must exist as _get_key generates it.
            encrypted_data = salt + ciphertext if salt else ciphertext
            metadata["method"] = self.MethodType.PASSPHRASE
        else:
            # For auto-generated key encryption, prepend the key itself to the ciphertext.
            # The key is separated from the actual ciphertext by AUTO_KEY_SEP.
            # This allows decryption without needing external key management for this mode.
            encrypted_data = key + self.AUTO_KEY_SEP + ciphertext
            metadata["method"] = self.MethodType.AUTO

        return encrypted_data, metadata

    def decrypt(self, ciphertext: Ciphertext, metadata: Metadata, passphrase: str | None = None) -> str:
        """Decrypts the provided ciphertext using the method specified in metadata.

        This method supports two modes of decryption, corresponding to the encryption
        methods:
        1.  **Passphrase-based**: If `metadata["method"]` is "passphrase", this
            method expects a `passphrase` to be provided. It extracts the salt
            from the beginning of the `ciphertext`, derives the decryption key
            using the passphrase and salt (via `_get_key`), and then decrypts
            the remaining part of the `ciphertext`.
        2.  **Auto-generated key**: If `metadata["method"]` is "auto" (or if no
            method is specified, "auto" is assumed), this method expects the
            decryption key to be prepended to the `ciphertext`, separated by
            `AUTO_KEY_SEP`. It splits the `ciphertext` to retrieve the key and
            the actual encrypted data, then uses this key for decryption.

        The Fernet symmetric decryption algorithm is used for the actual decryption.

        Args:
            ciphertext: The encrypted data.
                If passphrase-based, this is `salt + encrypted_content`.
                If auto-key based, this is `key + b"|" + encrypted_content`.
            metadata: A dictionary containing information about the
                encryption process, crucially the `method` ("passphrase" or "auto").
            passphrase: The secret phrase used for encryption if the method was
                "passphrase". Required for passphrase-based decryption.

        Returns:
            The decrypted data as a UTF-8 string.

        Raises:
            DecryptionError: If decryption fails due to various reasons,
                such as a missing passphrase for passphrase-based decryption,
                an invalid passphrase, an invalid key, corrupted ciphertext,
                or an unknown encryption method.
        """
        method = metadata.get("method", self.MethodType.AUTO)
        match method:
            case self.MethodType.PASSPHRASE:
                if passphrase is None:
                    raise DecryptionError("Passphrase required for decryption.")  # noqa: TRY003
                # The salt is assumed to be the first 16 bytes, as generated by os.urandom(16) in _get_key.
                salt = ciphertext[:16]
                actual_ciphertext = ciphertext[16:]
                key, _ = _get_key(passphrase, iterations=self.iterations, algorithm=self.algorithm, salt=salt)
                cipher = Fernet(key)
                try:
                    decrypted_data = cipher.decrypt(actual_ciphertext)
                except InvalidToken as e:
                    raise DecryptionError("Invalid passphrase or corrupted data.") from e  # noqa: TRY003
                except KeyError as e:
                    raise DecryptionError("Invalid key.") from e  # noqa: TRY003

            case self.MethodType.AUTO:
                # In "auto" mode, the key is prepended to the ciphertext, separated by AUTO_KEY_SEP.
                key_parts = ciphertext.split(self.AUTO_KEY_SEP, 1)
                if len(key_parts) != 2:
                    # This indicates the ciphertext is not in the expected format (key|data).
                    raise DecryptionError(
                        "Invalid ciphertext format for auto mode. Expected key and data separated by '|'."
                    )  # noqa: TRY003
                key, actual_ciphertext = key_parts
                cipher = Fernet(key)
                try:
                    decrypted_data = cipher.decrypt(actual_ciphertext)
                except InvalidToken as e:
                    # This can happen if the embedded key is incorrect or the ciphertext is corrupted.
                    raise DecryptionError(
                        "Failed to decrypt the data with the auto-embedded key. The ciphertext may be corrupted."
                    ) from e  # noqa: TRY003
            case _:
                # If the method specified in metadata is not recognized.
                raise DecryptionError(f"Unknown encryption method: {method}")  # noqa: TRY003

        return decrypted_data.decode("utf-8")


def get_hash(data: bytes) -> str:
    """
    Generate a SHA-256 hash of the provided data.

    Args:
        data: The bytes to hash

    Returns:
        Hexadecimal string representation of the hash
    """
    return hashlib.sha256(data).hexdigest()


def _get_key(
    passphrase: str | None, algorithm: hashes.HashAlgorithm, iterations: int, salt: bytes | None = None
) -> tuple[Cipherkey, Salt | None]:
    """
    Generate or derive an encryption key.

    Args:
        passphrase: If provided, derive key from this phrase
        salt: Optional salt for key derivation

    Returns:
        Tuple of (key, salt). If passphrase is None, salt will be None.
    """
    if passphrase is None:
        key = Fernet.generate_key()
        return key, None

    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=algorithm, length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return key, salt
