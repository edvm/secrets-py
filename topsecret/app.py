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

"""Application entry point for the Top Secret application."""

from threading import Lock
from typing import Optional

from topsecret.infra.cipher import aes
from topsecret.infra.storage import inmem
from topsecret.services.encryption import EncryptionService


class App:
    """A class responsible for managing the application's core services.

    Attributes:
            encryption_service (EncryptionService): The service used for encryption
                    and decryption operations.
    """

    _instance: Optional["App"] = None
    _lock: Lock = Lock()

    def __init__(self, encryption_service: EncryptionService) -> None:
        """Initializes the App with an encryption service.

        Note:
                This constructor should generally not be called directly.
                Use the `get_instance` class method to obtain the singleton instance.

        Args:
                encryption_service (EncryptionService): An instance of the
                        EncryptionService to be used by the application.
        """
        self.encryption_service = encryption_service

    @classmethod
    def get_instance(cls) -> "App":
        """Gets the singleton instance of the App.

        If an instance does not already exist, it creates one with a default values.

        Returns:
                App: The singleton instance of the App.
        """
        with cls._lock:
            if cls._instance is None:
                encryption_service = EncryptionService(
                    cipher=aes.PKCS7AESCipher(), storage=inmem.InMemStorage(), hashfn=aes.get_hash
                )
                cls._instance = cls(encryption_service)
        return cls._instance
