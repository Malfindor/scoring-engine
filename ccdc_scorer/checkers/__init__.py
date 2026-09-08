"""Protocol checker registry.

Importing this package registers every built-in checker.
"""

from . import directory, dns, http, mail, remote, transfer  # noqa: F401
from .base import CHECKERS, get_checker, supported_types

__all__ = ["CHECKERS", "get_checker", "supported_types"]
