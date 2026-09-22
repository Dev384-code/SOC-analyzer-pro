from datetime import datetime


def format_timestamp(value: str) -> str:
    return datetime.fromisoformat(value).strftime("%b %d, %Y %H:%M UTC")


def severity_class(value: str) -> str:
    return value.lower().replace(" ", "-")
