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
