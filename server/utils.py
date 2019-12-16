import random
import string
from datetime import datetime

string_length = 8


class SingletonMeta(type):

    __instance = None

    def __call__(cls):
        if not isinstance(cls.__instance, cls):
            cls.__instance = super().__call__()
        return cls.__instance


def generate_string() -> str:
    """Generate random string.

    Method generates random string with digits and latin letters.

    Returns:
        str: random string.

    """

    letters = string.ascii_letters
    digits = string.digits

    return ''.join(random.choice(letters + digits) for i in range(string_length))


def convert_date(timestamp: float) -> str:
    """Convert date from timestamp to string.

    Example of date format: 2019-09-05 11:22:33.

    Args:
        timestamp (float): date timestamp.

    Returns:
        str: converted date.

    """

    return datetime.fromtimestamp(timestamp).strftime("%Y.%m.%d %H:%M:%S")
