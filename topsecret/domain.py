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

import typing as t

K = t.TypeVar("K", contravariant=True)
V = t.TypeVar("V")

Hash = str
Metadata = dict[str, str]
Cipherkey = bytes
Salt = bytes
Ciphertext = bytes


class CipherProtocol(t.Protocol):
    """Defines a protocol for cryptographic operations, specifically encrypting and
    decrypting byte data.

    This protocol outlines the contract for classes that provide encryption and
    decryption functionalities. Implementations are expected to handle the
    conversion of plaintext data into a secure, encrypted format (ciphertext)
    and vice-versa. The protocol supports operations with an optional passphrase,
    allowing for both passphrase-based encryption and potentially other key
    management schemes.

    The `Ciphertext` and `Metadata` types mentioned in method signatures are
    placeholders for the specific types that an implementing class would use for
    encrypted data and its associated metadata, respectively.

    Attributes:
        AUTO_KEY_SEP (bytes): A class-level constant representing a byte sequence
            (b"|"). This separator is intended for use in "auto encryption"
            scenarios. While the specific mechanism of "auto encryption" is not
            defined by this protocol, this separator likely plays a role in
            demarcating or structuring data when keys are managed automatically
            or embedded within the ciphertext or metadata.
    """

    """Encrypt/Decrypt bytes."""

    AUTO_KEY_SEP: bytes = b"|"  # for auto encryption

    def encrypt(self, data: bytes, passphrase: str | None = None) -> tuple[Ciphertext, Metadata]:
        """Encrypts the provided byte data.

        This method takes raw byte data and an optional passphrase, processes it
        through an encryption algorithm, and returns the resulting ciphertext
        along with associated metadata. The metadata is crucial as it may contain
        information required for successful decryption, such as initialization
        vectors (IVs), salts, or parameters related to the encryption algorithm
        or key derivation.

        If a passphrase is not provided, the implementation is expected to handle
        key management. This could involve generating a new key, using a
        pre-configured key, or employing a mechanism related to "auto encryption"
        (potentially using `AUTO_KEY_SEP`). The specifics of this behavior are
        left to the implementing class.

        Args:
            data (bytes): The raw byte data to be encrypted.
            passphrase (str | None): An optional passphrase to be used for deriving
                the encryption key. If None, the encryption method should define
                its behavior for key generation or retrieval according to its
                key management strategy.

        Returns:
            tuple[Ciphertext, Metadata]: A tuple containing two elements:
                - Ciphertext: The encrypted version of the input `data`. The exact
                type or structure of `Ciphertext` is not defined by this protocol
                but is expected to be the encrypted payload.
                - Metadata: Ancillary information required or useful for the
                decryption process. This could include salts, IVs, algorithm
                identifiers, or other cryptographic parameters. The exact type
                or structure of `Metadata` is also implementation-dependent.
        """
        ...

    def decrypt(self, ciphertext: Ciphertext, metadata: Metadata, passphrase: str | None = None) -> str:
        """Decrypts the given ciphertext back into its original string form.

        This method takes ciphertext and its associated metadata, along with an
        optional passphrase, to reverse the encryption process. It attempts to
        decrypt the data and then decodes the resulting bytes into a string.
        The successful execution of this method relies on the correct ciphertext,
        metadata, and, if used during encryption, the correct passphrase.

        The metadata provided must correspond to the metadata generated during the
        encryption of the `ciphertext`. If a passphrase was used for encryption,
        the same passphrase must be provided for decryption. If no passphrase was
        used (e.g., in an "auto encryption" scenario where the key is managed
        differently), providing `None` for the passphrase argument should allow
        the decryption process to proceed using the implementation's key management
        strategy.

        The return type of `str` implies that the original data, before encryption,
        was text that was encoded into bytes (e.g., using UTF-8) and, upon
        decryption, is decoded back into a string using an appropriate encoding
        assumed by the implementation.

        Args:
            ciphertext (Ciphertext): The encrypted data to be decrypted. This should
                be the `Ciphertext` object obtained from a compatible `encrypt` method.
            metadata (Metadata): The metadata associated with the `ciphertext`. This
                should be the `Metadata` object obtained from a compatible `encrypt`
                method, containing all necessary information for decryption.
            passphrase (str | None): The passphrase that was used to encrypt the
                data. If no passphrase was used during encryption (e.g., key was
                auto-generated and managed), this should be `None`.

        Returns:
            str: The decrypted data, decoded into a string.

        Raises:
            Exception: While not explicitly defined in the protocol, implementations
                are expected to raise an appropriate exception (e.g., a custom
                `DecryptionError`, `ValueError`, or a cryptography-specific error)
                if the decryption fails. This could be due to an incorrect
                passphrase, corrupted data, tampered ciphertext/metadata, or
                mismatched cryptographic parameters.
        """
        ...


class CipherStorageProtocol(t.Generic[K, V], t.Protocol):
    """Protocol for a generic key-value storage mechanism.

    This class defines a protocol that specifies an interface for
    storing, retrieving, and checking the existence of key-value pairs. It is
    designed to be generic, utilizing type variables `K` for keys and `V` for
    values. This allows concrete implementations to define the specific types
    they handle, promoting flexibility and type safety.

    The primary purpose of this protocol is to abstract the underlying storage
    mechanism. Implementers could use various backends, such as in-memory
    dictionaries for testing, databases for persistent storage, or distributed
    caches for scalable solutions. By adhering to this protocol, different
    storage implementations can be used interchangeably within an application.

    In the context of cipher management or secure data handling (as suggested by
    the name "CipherStorageProtocol"), `K` might represent a unique identifier
    for a cryptographic key, a cipher suite, or a protected data entry. `V`
    could then be the actual cryptographic material (e.g., an encryption key,
    a PGP key object), a configuration object for a cipher, or the encrypted
    data itself.

    Implementations are expected to provide the logic for:
    - `retrieve(key)`: Fetching a value given its key.
    - `store(key, value)`: Persisting a key-value pair.
    - `contains(key)`: Verifying if a key is present in the storage.

    Args:
        K: TypeVar representing the type of the keys in the storage. This allows
            for flexibility in choosing key types, such as strings, integers, or
            custom hashable objects.
        V: TypeVar representing the type of the values in the storage. This allows
            for storing various kinds of data, from simple types to complex objects
            or serialized data.
    """

    def retrieve(self, key: K) -> V | None:
        """Retrieves the value associated with the given key.

        This method attempts to find an entry in the storage that matches the
        provided key. If a corresponding value exists, it is returned. If the
        key is not found in the storage, this method must return `None`.
        This explicit `None` return for non-existent keys allows callers to
        reliably distinguish between a key not being found and a key being
        associated with a `None` value (if `V` itself can be `NoneType`).

        Args:
            key (K): The key whose associated value is to be retrieved. The type
                of the key must match the generic type `K` defined by the
                implementing class.

        Returns:
            V | None: The value associated with the specified `key` if it exists
                within the storage. Returns `None` if the `key` is not found.
        """
        ...

    def store(self, key: K, value: V) -> None:
        """Stores a key-value pair in the storage.

        This method is responsible for persisting the given `value` under the
        specified `key`. If the `key` already exists in the storage, the
        behavior (e.g., overwrite the existing value, raise an error, or ignore
        the operation) is typically defined by the concrete implementation of
        this protocol. However, a common expectation for key-value stores is
        that the new value will replace any existing value for that key.

        The method is expected to complete the storage operation and ensure the
        key-value pair is durably or appropriately stored according to the
        implementation's guarantees.

        Args:
            key (K): The key under which the `value` is to be stored. Its type
                must conform to the generic type `K` of the protocol.
            value (V): The value to be stored. Its type must conform to the
                generic type `V` of the protocol.

        Returns:
            None: This method does not return any value.
        """
        ...

    def contains(self, key: K) -> bool:
        """Checks if a key exists in the storage.

        This method determines whether the storage holds any value associated
        with the given `key`. It provides an efficient way to query the
        existence of a key without incurring the potential overhead of
        retrieving the actual value (as the `retrieve` method would do).

        This is particularly useful for pre-flight checks before attempting
        a `retrieve` or `store` operation (e.g., to decide whether to update
        or insert), or for any logic that depends on the presence or absence
        of a key.

        Args:
            key (K): The key to check for existence in the storage. Its type
                must conform to the generic type `K` of the protocol.

        Returns:
            bool: `True` if the `key` is found in the storage, `False` otherwise.
        """
        ...


class DecryptionError(Exception):
    """Custom exception raised when decryption fails.

    This exception is typically raised when an attempt to decrypt data does not
    succeed. This can occur for several reasons, such as:
        1. The provided passphrase or key is incorrect.
        2. The ciphertext has been tampered with or is corrupted.
        3. The encryption algorithm or mode of operation used during encryption
           is different from what is being used for decryption.
        4. The ciphertext is not in the expected format.

    Attributes:
        message (str): A human-readable string describing the error.
            If no message is provided during instantiation, a default
            message is used.
    """

    def __init__(self, message: str = ""):
        """Initializes a new DecryptionError instance.

        Args:
            message (str, optional): A custom message describing the specific
                decryption error. If an empty string or no message is provided,
                a default error message "Failed to decrypt the data. The
                ciphertext may be corrupted or the passphrase is incorrect."
                will be used. This allows for more specific error reporting
                when the cause of the decryption failure is known, while
                providing a generic message otherwise.
        """
        default = "Failed to decrypt the data. The ciphertext may be corrupted or the passphrase is incorrect."
        super().__init__(message or default)
