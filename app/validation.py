"""Input rules shared by the API, the pages and the operator commands."""
import unicodedata
from typing import Annotated

from fastapi import Path
from pydantic import AfterValidator

# Joiners are part of emoji sequences and of some scripts.
_ALLOWED_FORMAT_CHARACTERS = {"‌", "‍"}


def is_unsafe_character(character: str) -> bool:
    """Control characters (NUL is refused by PostgreSQL), line separators and
    invisible formatting such as bidirectional overrides, which make a name
    display as something it is not."""
    category = unicodedata.category(character)
    return category in {"Cc", "Cs", "Zl", "Zp"} or (
        category == "Cf" and character not in _ALLOWED_FORMAT_CHARACTERS
    )


def has_unsafe_characters(value: str) -> bool:
    return any(is_unsafe_character(character) for character in value)


def without_unsafe_characters(value: str) -> str:
    return "".join(character for character in value if not is_unsafe_character(character))


def _display_text(value: str) -> str:
    if has_unsafe_characters(value):
        raise ValueError("must not contain control or invisible formatting characters")
    return value


DisplayText = AfterValidator(_display_text)

# A token or account in a URL path: the service creates them as UUIDs.
ResourceId = Annotated[str, Path(min_length=1, max_length=36, pattern=r"^[0-9A-Za-z-]+$")]
