# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import random
import string
from datetime import datetime

string_length = 8


class SingletonMeta(type):
    """Meta class for singletons.

    """

    def __call__(cls):
        pass


def generate_string() -> str:
    """Generate random string.

    Method generates random string with digits and latin letters.

    Returns:
        str: random string.

    """

    pass


def convert_date(timestamp: float) -> str:
    """Convert date from timestamp to string.

    Example of date format: 2019-09-05 11:22:33.

    Args:
        timestamp (float): date timestamp.

    Returns:
        str: converted date.

    """

    pass
