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

    def encrypt(self, data: bytes, passphrase: str | None = None) -> tuple[Ciphertext, Metadata]:
        """
        Encrypt the provided plaintext.

        This method supports two encryption modes:

        1. Passphrase-based (RECOMMENDED): When a passphrase is provided, the data
           is encrypted using a key derived from the passphrase. This is the more
           secure option as the encryption key is not stored with the ciphertext.

        2. Auto-generated key: When no passphrase is provided, a random key is
           generated and embedded within the returned ciphertext. NOTE: This mode
           is less secure as anyone with access to the ciphertext can extract the
           key. Use this only for non-sensitive data or when key management is
           handled separately.

        Args:
            plaintext: The text to encrypt
            passphrase: Optional secret phrase for encryption

        Returns:
            A tuple containing (ciphertext, metadata)
        """
        key, salt = _get_key(passphrase, algorithm=self.algorithm, iterations=self.iterations)
        cipher = Fernet(key)
        ciphertext = cipher.encrypt(data)

        metadata: Metadata = {}
        if passphrase:
            encrypted_data = salt + ciphertext if salt else ciphertext
            metadata["method"] = self.MethodType.PASSPHRASE
        else:
            encrypted_data = key + b"|" + ciphertext
            metadata["method"] = self.MethodType.AUTO

        return encrypted_data, metadata

    def decrypt(self, ciphertext: Ciphertext, metadata: Metadata, passphrase: str | None = None) -> str:
        """
        Decrypt the provided ciphertext using the appropriate method.

        Args:
            ciphertext: The encrypted data
            metadata: Information about how the data was encrypted
            passphrase: Secret phrase required for passphrase-based encryption

        Returns:
            The decrypted text

        Raises:
            DecryptionError: If decryption fails for any reason
        """
        method = metadata.get("method", self.MethodType.AUTO)
        match method:
            case self.MethodType.PASSPHRASE:
                if passphrase is None:
                    raise DecryptionError("Passphrase required for decryption.")  # noqa: TRY003
                salt = ciphertext[:16]
                actual_ciphertext = ciphertext[16:]
                key, _ = _get_key(passphrase, iterations=self.iterations, algorithm=self.algorithm, salt=salt)
                cipher = Fernet(key)
                try:
                    decrypted_data = cipher.decrypt(actual_ciphertext)
                except InvalidToken as e:
                    raise DecryptionError("Invalid passphrase") from e  # noqa: TRY003
                except KeyError as e:
                    raise DecryptionError("Invalid key") from e  # noqa: TRY003

            case self.MethodType.AUTO:
                key_parts = ciphertext.split(self.AUTO_KEY_SEP, 1)
                if len(key_parts) != 2:
                    raise DecryptionError("Invalid ciphertext format")  # noqa: TRY003
                key, actual_ciphertext = key_parts
                cipher = Fernet(key)
                try:
                    decrypted_data = cipher.decrypt(actual_ciphertext)
                except InvalidToken as e:
                    raise DecryptionError("Failed to decrypt the data. The ciphertext may be corrupted.") from e  # noqa: TRY003
            case _:
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
