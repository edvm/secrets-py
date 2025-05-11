from unittest.mock import Mock, patch

import pytest

from topsecret.app import App
from topsecret.services.encryption import EncryptionService


class TestApp:
    @pytest.fixture
    def mock_encryption_service(self):
        """Mock encryption service."""
        return Mock(spec=EncryptionService)

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton instance."""
        App._instance = None
        yield
        App._instance = None

    def test_init(self, mock_encryption_service):
        """Test App initialization."""
        app = App(mock_encryption_service)
        assert app.encryption_service == mock_encryption_service

    @pytest.mark.usefixtures("reset_singleton")
    def test_get_instance_creates_new_instance(self):
        """Test creating a new instance."""
        with patch("topsecret.app.EncryptionService") as mock_service_class:
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            assert App._instance is None
            app = App.get_instance()
            assert app is not None
            assert App._instance == app

    @pytest.mark.usefixtures("reset_singleton")
    def test_get_instance_initializes_encryptor(self):
        """Test initializing EncryptionService."""
        with patch("topsecret.app.EncryptionService") as mock_encryption_service:
            mock_encryptor = Mock()
            mock_encryption_service.return_value = mock_encryptor

            App.get_instance()
            mock_encryption_service.assert_called_once()

    @pytest.mark.usefixtures("reset_singleton")
    def test_get_instance_initializes_storage(self):
        """Test initializing storage."""
        with patch("topsecret.app.inmem.InMemStorage") as mock_storage_class:
            mock_storage = Mock()
            mock_storage_class.return_value = mock_storage

            App.get_instance()
            mock_storage_class.assert_called_once()

    @pytest.mark.usefixtures("reset_singleton")
    def test_get_instance_returns_existing_instance(self, mock_encryption_service):
        """Test returning existing instance."""
        App._instance = App(mock_encryption_service)
        original_instance = App._instance

        instance = App.get_instance()
        assert instance == original_instance

    @pytest.mark.usefixtures("reset_singleton")
    def test_get_instance_does_not_create_new_service_if_instance_exists(self, mock_encryption_service):
        """Test not creating new service if instance exists."""
        App._instance = App(mock_encryption_service)

        with patch("topsecret.app.EncryptionService") as mock_service_class:
            App.get_instance()
            mock_service_class.assert_not_called()

    @pytest.mark.usefixtures("reset_singleton")
    def test_subsequent_get_instance_returns_first_instance(self):
        """Test subsequent calls return first instance."""
        instance1 = App.get_instance()
        instance2 = App.get_instance()
        instance3 = App.get_instance()
        assert instance1 is instance2 is instance3

    @pytest.mark.usefixtures("reset_singleton")
    def test_multithreaded_singleton_returns_same_instance(self):
        """Test singleton returns same instance across threads."""
        import threading

        instances = []

        def get_instance():
            instances.append(App.get_instance())

        threads = [threading.Thread(target=get_instance) for _ in range(10)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        for instance in instances[1:]:
            assert instance is instances[0]
