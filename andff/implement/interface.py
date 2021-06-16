import os
import time
import datetime
import json
import subprocess
from andff import setting
from .logger import def_logger as logger


def get_cur_time():  # ms
    return int(round(time.time() * 1000))


def readable_time(t, fmt='%d hrs, %d min, %d sec'):
    if not isinstance(t, int):
        return t

    t /= 1000  # ms
    h = t // 60 // 60
    m = t // 60 - h * 60
    s = t - m * 60 - h * 60 * 60
    return fmt % (h, m, s)


def get_config(cfg):
    if not os.path.isfile(cfg):
        logger.error('config file not found! {}'.format(cfg))
        return None

    with open(cfg) as f:
        return json.load(f)


def checkout_args_types(args):
    """
    :param args:
        eg:
        [
            {"type": "int", "size": 4},
            {"type": "pointer", "size": 0},
            {"type": "pbl_int", "size": 0}
        ]
    :return:
    """
    support = ['int', 'int64', 'pointer', 'pbl_int']
    args_types = []
    for x in args:
        t = x['type']
        if t not in support:
            logger.error('{} arg type not support!'.format(t))
            return None

        if t.startswith('pbl'):
            t = t.split('_')[-1]
        args_types.append(t)
    return args_types


def fri_compile(**kwargs):
    cfg = get_config(kwargs.get('config'))
    if not cfg:
        return False

    comp = cfg.get('compile')
    fcj = cfg.get('fcj')
    script = cfg.get('script')
    if not comp or not script or not fcj:
        return False

    if os.path.isfile(script):
        os.remove(script)

    template = comp.get('template')
    target_module = comp.get('target_module')
    target_function = comp.get('target_function')
    ret_type = comp.get('ret_type')
    args = comp.get('args')
    if not template or not target_module or not target_function or not ret_type or not args:
        return False

    args_types = checkout_args_types(args)
    if not args_types:
        return False

    tf = os.path.join(setting.TEMPLATE_DIR, template)
    if not os.path.isfile(tf):
        logger.error('template file not found! {}'.format(tf))
        return False

    dump_js = []

    with open(tf) as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith('//'):
            pass
        elif 'REP_TARGET_MODULE' in line:
            line = line.replace('REP_TARGET_MODULE', target_module)
        elif 'REP_TARGET_FUNCTION' in line:
            line = line.replace('REP_TARGET_FUNCTION', target_function)
        elif 'REP_TARGET_RET_TYPE' in line:
            line = line.replace('REP_TARGET_RET_TYPE', ret_type)
        elif 'REP_TARGET_ARGS_PROTO' in line:
            line = line.replace('REP_TARGET_ARGS_PROTO', '{}'.format(args))
        elif 'REP_TARGET_ARGS_TYPES' in line:
            line = line.replace('REP_TARGET_ARGS_TYPES', '{}'.format(args_types))
        else:
            pass
        dump_js.append(line)

    dump_file = '{}.tmp'.format(tf)
    with open(dump_file, 'w') as f:
        f.write(''.join(dump_js))

    # logger.info('dumps: {}'.format(dump_file))

    args = [fcj, dump_file, '-o', script]
    try:
        subprocess.check_output(args)
    except Exception as e:
        logger.error('compile except! {}'.format(e))
        return False

    if not os.path.isfile(script):
        logger.error('compile failed!')
        return False

    logger.success('compile success! {}'.format(script))

    return True


def fri_fuzz(**kwargs):
    from .fuzz import Fuzz
    cfg = get_config(kwargs.get('config'))
    if not cfg:
        return False

    output_dir = cfg.get('output')
    if not output_dir:
        output_dir = os.path.join(
            setting.DATA_DIR,
            '{}_{}'.format(cfg.get('target'), datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
        )
    if os.path.isdir(output_dir):
        os.remove(output_dir)
    os.mkdir(output_dir)
    cfg['output'] = output_dir

    fuzz = Fuzz(**cfg)
    fuzz.run()
