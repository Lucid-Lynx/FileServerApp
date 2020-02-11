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

    home_dir = str(Path.home())
    download_dir = '{}/Downloads'.format(home_dir)

    def __init__(self, daemon: bool = False):
        Thread.__init__(self)
        self.id = str(uuid4())
        self.daemon = daemon

        if not os.path.exists(self.download_dir):
            os.mkdir(self.download_dir)

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

        if is_signed:
            file_service = FileServiceSigned()
        else:
            file_service = FileService()

        file_data = file_service.get_file_data(filename, user_id)
        full_filename = '{}/{}.{}'.format(self.download_dir, filename, file_service.extension)

        i = 0
        while os.path.exists(full_filename):
            i += 1
            full_filename = '{}/{}({}).{}'.format(self.download_dir, filename, i, file_service.extension)

        with open(full_filename, 'wb') as file_handler:
            data = bytes(file_data['content'], 'utf-8')
            file_handler.write(data)
            logger.info('Thread Id: {}. File {} is successfully downloaded'.format(self.id, filename))

            return 'File {}.{} is successfully downloaded'.format(filename, file_service.extension)


class FileLoader(BaseLoader):
    """Not daemon thread file loader class.

    """

    def __init__(self, filename: str, user_id: int = None, is_signed: bool = False):
        super().__init__(daemon=False)
        assert user_id, 'User Id is not set'
        self.filename = filename
        self.is_signed = is_signed
        self.user_id = user_id
        self.state = 'inited'
        self.message = None

    def run(self):
        """Run thread.

        """

        self.state = 'started'
        logger.info('Thread Id: {}. Start downloading file'.format(self.id))

        try:
            time.sleep(5)
            self.state = 'finished'
            self.message = self.download_file(self.filename, self.is_signed, self.user_id)

        except (AssertionError, ValueError) as err:
            self.state = 'error'
            self.message = err
            logger.error('Thread Id: {}. An error occured: {}'.format(self.id, err))

        logger.info('Thread Id: {}. Stop downloading file'.format(self.id))


class QueuedLoader(BaseLoader):
    """Daemon thread file loader class.

    """

    def __init__(self, queue: Queue):
        super().__init__(daemon=True)
        self.queue = queue

    def run(self):
        """Run thread.

        """

        logger.info('Thread Id: {}. Start working daemon'.format(self.id))

        while True:
            request = self.queue.get()
            time.sleep(5)

            try:
                self.download_file(request['filename'], request['is_signed'], request['user_id'])

            except (AssertionError, ValueError) as err:
                logger.error('Thread Id: {}. An error occured: {}'.format(self.id, err))

            self.queue.task_done()
