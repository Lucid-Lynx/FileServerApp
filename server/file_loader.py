# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import logging
import time
from uuid import uuid4
from threading import Thread
from queue import Queue
from pathlib import Path
from server.file_service import FileService, FileServiceSigned

logger = logging.getLogger(__name__)


class BaseLoader(Thread):
    """Base file loader class.

    """

    def __init__(self, daemon: bool = False):
        pass

    def download_file(self, filename: str, is_signed: bool, user_id: int) -> str:
        """Download file into /home/{user_name}.

        Args:
            filename (str): file name,
            is_signed (bool): check or not file signature,
            user_id (int): user Id.

        Returns:
            Str with success message.

        Raises:
            AssertionError: if file does not exist, filename format is invalid, signatures are not match,
            signature file does not exist,
            ValueError: if security level is invalid.

        """

        pass


class FileLoader(BaseLoader):
    """Not daemon thread file loader class.

    """

    def __init__(self, filename: str, user_id: int = None, is_signed: bool = False):
        pass

    def run(self):
        """Run thread.

        """

        pass


class QueuedLoader(BaseLoader):
    """Daemon thread file loader class.

    """

    def __init__(self, queue: Queue):
        pass

    def run(self):
        """Run thread.

        """

        pass
