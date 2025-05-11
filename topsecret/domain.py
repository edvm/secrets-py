import typing as t

K = t.TypeVar("K", contravariant=True)
V = t.TypeVar("V")

Hash = str
Metadata = dict[str, str]
Cipherkey = bytes
Salt = bytes
Ciphertext = bytes


class CipherProtocol(t.Protocol):
    """Encrypt/Decrypt bytes."""

    AUTO_KEY_SEP: bytes = b"|"  # for auto encryption

    def encrypt(self, data: bytes, passphrase: str | None = None) -> tuple[Ciphertext, Metadata]: ...

    def decrypt(self, ciphertext: Ciphertext, metadata: Metadata, passphrase: str | None = None) -> str: ...


class CipherStorageProtocol(t.Generic[K, V], t.Protocol):
    """Store ciphertexts."""

    def retrieve(self, key: K) -> V | None: ...

    def store(self, key: K, value: V) -> None: ...

    def contains(self, key: K) -> bool: ...


class DecryptionError(Exception):
    """Decryption failed."""

    def __init__(self, message: str = ""):
        default = "Failed to decrypt the data. The ciphertext may be corrupted or the passphrase is incorrect."
        super().__init__(message or default)
