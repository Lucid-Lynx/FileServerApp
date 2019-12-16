# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import logging
import time
from uuid import uuid4
from threading import Thread
from pathlib import Path
from server.file_service import FileService, FileServiceSigned

logger = logging.getLogger("File Loader Logger")


class FileLoader(Thread):

    home_dir = str(Path.home())
    download_dir = '{}/Downloads'.format(home_dir)

    def __init__(self, filename, user_id=None, is_signed=False):
        Thread.__init__(self)

        assert user_id, 'User Id is not set'

        self.id = str(uuid4())
        self.filename = filename
        self.user_id = user_id
        self.state = 'inited'
        self.message = None

        if is_signed:
            self.file_service = FileServiceSigned()
        else:
            self.file_service = FileService()

        if not os.path.exists(self.download_dir):
            os.mkdir(self.download_dir)

    def run(self):

        self.state = 'started'
        logger.info('Thread Id: {}. Start downloading file'.format(self.id))

        try:
            file_data = self.file_service.get_file_data(self.filename, self.user_id)
            full_filename = '{}/{}.{}'.format(self.download_dir, self.filename, self.file_service.extension)

            i = 0
            while os.path.exists(full_filename):
                i += 1
                full_filename = '{}/{}({}).{}'.format(self.download_dir, self.filename, i, self.file_service.extension)

            with open(full_filename, 'wb') as file_handler:
                data = bytes(file_data['content'], 'utf-8')
                file_handler.write(data)
                logger.info('Thread Id: {}. File {} is successfully downloaded'.format(self.id, self.filename))

            self.state = 'finished'
            self.message = 'File {}.{} is successfully downloaded'.format(self.filename, self.file_service.extension)
            logger.info('Thread Id: {}. Stop downloading file'.format(self.id))

        except (AssertionError, ValueError) as err:
            self.state = 'error'
            self.message = err
            logger.error('Thread Id: {}. An error occured: {}'.format(self.id, err))
