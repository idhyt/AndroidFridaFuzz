import sys
from andff import setting


def logger_handle_registered(**kwargs):
    from loguru import logger as default_logger

    console_level = kwargs.get('console_level', 'WARNING')
    record_level = kwargs.get('record_level', 'TRACE')
    record_file = kwargs.get('record_file', './trace.log')

    handlers = [
        {
            'sink': sys.stderr,
            'level': console_level,
            'format': '<green>{time:YYYY-MM-DD at HH:mm:ss}</green> | '
                      '<level>{level: <8}</level> | '
                      '<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - '
                      '<level>{message}</level>' if console_level == 'DEBUG' else '<level>{message}</level>',
        },
        {
            'sink': record_file,
            'format': '{time:YYYY-MM-DD at HH:mm:ss} | {level} | {name}:{function}:{line} - {message}',
            'level': record_level,
            'rotation': '500 MB'
        }
    ]
    try:
        default_logger.remove(0)
    except Exception as e:
        print('logger register error! {}'.format(e))

    default_logger.configure(handlers=handlers)

    return default_logger


def_logger = logger_handle_registered(
    console_level=setting.LOGGER_CONSOLE,
    record_level=setting.LOGGER_RECORD,
    record_file=setting.LOGGER_FILE
)
