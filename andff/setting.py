import os

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(CUR_DIR), 'data')

# logger level
LOGGER_FILE = os.path.join(DATA_DIR, 'log.txt')
LOGGER_CONSOLE = 'INFO'
LOGGER_RECORD = 'DEBUG'

TEMPLATE_DIR = os.path.join(CUR_DIR, 'template')
