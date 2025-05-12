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

from typing import Callable

from topsecret.domain import CipherProtocol, CipherStorageProtocol, Ciphertext, DecryptionError, Hash


class EncryptionService:
    """Provides encryption and decryption services.

    This class orchestrates the encryption and decryption processes,
    utilizing a specified cipher for cryptographic operations, a storage
    mechanism for persisting encrypted data, and a hash function for
    generating unique identifiers (keys) for stored ciphertexts.

    Attributes:
        cipher: The cipher object used for encryption and
            decryption.
        storage: The storage object used for storing
            and retrieving ciphertexts.
        hahsfn: The hash function used to generate
            keys for storing ciphertexts.
    """

    def __init__(self, cipher: CipherProtocol, storage: CipherStorageProtocol, hashfn: Callable[[bytes], str]) -> None:
        """Initializes the instance with a cipher, storage, and hash function.

        Args:
            cipher: An object conforming to the CipherProtocol, used for
                encryption and decryption operations.
            storage: An object conforming to the CipherStorageProtocol, used for
                storing and retrieving cipher-related data.
            hashfn: A callable that takes bytes as input and returns a string
                hash, used for hashing operations within the service.
        """
        self.cipher = cipher
        self.storage = storage
        self.hashfn = hashfn

    def encrypt(self, data: bytes, passphrase: str | None = None) -> tuple[Ciphertext, Hash]:
        """Encrypts the given data and stores it.

        This method encrypts the input data using the configured cipher.
        It then calculates a hash of the ciphertext and stores the
        ciphertext along with its metadata using this hash as the key.

        Args:
            data: The byte string to be encrypted.
            passphrase: An optional passphrase for encryption. If not
                provided, the cipher's default or pre-configured
                passphrase/key might be used.

        Returns:
            A tuple containing the ciphertext and its corresponding hash.
            The first element is the encrypted data (Ciphertext), and the
            second element is the hash (Hash) of the ciphertext.
        """
        ciphertext, metadata = self.cipher.encrypt(data, passphrase)
        hash_value = self.hashfn(ciphertext)
        value = (ciphertext, metadata)
        self.storage.store(key=hash_value, value=value)
        return ciphertext, hash_value

    def decrypt(self, hash_value: Hash, passphrase: str | None = None) -> str:
        """Decrypts a ciphertext retrieved from storage using a hash value.

        This method retrieves the encrypted data (ciphertext) and its associated
        metadata from storage using the provided `hash_value`. If the entry
        is not found, a `DecryptionError` is raised. Otherwise, it delegates
        the decryption process to the configured cipher object using the
        retrieved ciphertext, metadata, and the optionally provided `passphrase`.

        Args:
            hash_value (Hash): The unique identifier used to retrieve the
                ciphertext and metadata from storage.
            passphrase (str or None, optional): The passphrase for decryption.
                Defaults to None. The behavior when None is provided (e.g.,
                using a default key or requiring a passphrase explicitly if one
                is necessary for the cipher) depends on the specific cipher
                implementation.

        Returns:
            str: The decrypted plaintext string.

        Raises:
            DecryptionError: If no ciphertext is found in storage for the
                given `hash_value`.
            Exception: Propagated if the underlying `self.cipher.decrypt()`
                method fails. This can occur for various reasons, such as an
                incorrect passphrase, corrupted ciphertext, or other
                cipher-specific issues.
        """
        try:
            value = self.storage.retrieve(key=hash_value)
        except KeyError as e:
            raise DecryptionError("Ciphertext not found in storage.") from e  # noqa: TRY003

        if value is None:
            raise DecryptionError("Ciphertext not found in storage.")  # noqa: TRY003

        ciphertext, metadata = value
        return self.cipher.decrypt(ciphertext, metadata, passphrase)
