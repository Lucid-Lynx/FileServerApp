# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os

os.environ['DB_NAME'] = 'FileServer'
os.environ['DB_HOST'] = 'localhost'
os.environ['DB_USER'] = 'lucid'
os.environ['DB_PASSWORD'] = 'lynx'
os.environ['SESSION_DURATION_HOURS'] = '1'
os.environ['ADMIN_PASSWORD'] = 'admin1234'
os.environ['KEY_DIR'] = '../keys'
os.environ['DATE_FORMAT'] = '%Y-%m-%d %H:%M:%S'
os.environ['CRYPTO_CODE'] = '0101d08d-5c8e-4265-b2c3-b884d02b0cb4'
