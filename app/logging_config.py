import logging

APP_LOGGER = "token_generator"


def configure_logging(level: str = "INFO") -> None:
    """Send the app's audit and account logs to stderr.

    uvicorn only configures its own loggers. Without a handler of their own,
    records from the token_generator.* loggers fall through to Python's
    last-resort handler, which drops everything below WARNING, so INFO-level
    audit events (admin actions, logins) would never be written.
    """
    logger = logging.getLogger(APP_LOGGER)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    for name in ("token_generator.audit", "token_generator.account"):
        logging.getLogger(name).setLevel(min(logging.INFO, logger.level))
    logger.propagate = False
