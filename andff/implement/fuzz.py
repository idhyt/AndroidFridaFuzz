import os
import time
import random
import copy
from .logger import def_logger as logger
from .frida import Frida
from .interface import get_cur_time, readable_time


class InitialSeeds(object):
    def __init__(self):
        self.idx = 0
        self.seeds = []

    def add(self, filename):
        self.seeds.append(filename)

    def get(self):
        if self.idx < len(self.seeds):
            r = self.seeds[self.idx]
            self.idx += 1
            return r
        return None


class QEntry(object):
    def __init__(self):
        self.filename = ''
        self.size = 0
        self.num = 0
        self.was_fuzzed = False
        self.exec_ms = 0
        self.time = 0
        self.new_cov = False
        self.next = None


class Queue(object):
    def __init__(self, **kwargs):
        self.max_num = 0
        self.start = None
        self.cur = None
        self.top = None
        # use a dict for fast lookup by num
        self.dict = {}

        self.output_folder = kwargs.get('output')

    def add(self, buf, exec_ms, new_cov, stage, num):
        """

        :param buf:
        :param exec_ms:
        :param new_cov:
        :param stage: stage name: init / havoc / splice
        :param num:
        :return:
        """
        q = QEntry()
        q.filename = os.path.join(self.output_folder, 'id_%d_%s' % (num, stage))
        if new_cov:
            q.filename += '_cov'
        q.num = num
        q.exec_ms = exec_ms
        q.new_cov = new_cov
        q.time = get_cur_time()
        q.size = len(buf)
        with open(q.filename, 'wb') as f:
            f.write(buf)
        self.max_num = max(num, self.max_num)
        self.dict[num] = q
        if self.top:
            self.top.next = q
            self.top = q
        else:
            self.start = q
            self.top = q

    def get(self):
        if self.cur is None:
            self.cur = self.start
        elif self.cur.next is None:
            self.cur = self.start
        else:
            q = self.cur.next
            self.cur = q
        return self.cur

    def find_by_num(self, num):
        """
        q = self.start
        while q is not None:
            if q.num == num:
                return q
            q = q.next
        return None
        """
        return self.dict.get(num, None)

    def get_splice_target(self, q, buf):
        def locate_diffs(a, b):
            f_loc = None
            l_loc = None
            for i in range(min(len(a), len(b))):
                if a[i] != b[i]:
                    if f_loc is None:
                        f_loc = i
                    l_loc = i
            return f_loc, l_loc

        tid = random.randint(0, self.max_num)
        t = self.find_by_num(tid)
        while t is not None and (t.size < 2 or t.num == q.num):
            t = t.next
        if t is None:
            return None
        with open(t.filename, 'rb') as f:
            new_buf = f.read()
        f_diff, l_diff = locate_diffs(buf, new_buf)
        if f_diff is None or l_diff < 2 or f_diff == l_diff:
            return None
        split_at = random.randint(f_diff, l_diff - 1)
        return buf[:split_at] + new_buf[split_at:]


class FuzzStats(object):
    def __init__(self):
        self.target = None
        self.output = None
        # fuzz start time
        self.start_time = None
        # fuzz run time
        self.run_time = None
        # total execs
        self.total_execs = 0
        # exec last speed or total speed
        self.exec_speed = None
        # current exec stage name
        self.current_stage = '<init>'
        # [stage_cur, stage_max]
        self.stage_execs = [0, 0]
        # find total new path
        self.total_paths = 0
        # find new path last time
        self.last_new_path = 'not seen yet'
        # last exec nums
        self.last_execs = None
        # last execs time
        self.last_ms = 0
        # exec last speed or total speed
        self.exec_speed = 0
        # total crashes
        self.total_crashes = 0
        # last crash time
        self.last_crash = 'not seen yet'
        # total hangs
        self.total_hangs = 0
        # last hang time
        self.last_hang = 'not seen yet'
        # [queue_cur, queue_max]
        self.queue_size = [0, 0]
        #
        self.favored_paths = 0
        #
        self.pend_fav = 0
        #
        self.map_density = None
        # cycles_done
        self.queue_cycle = 0


class Fuzz(Frida):
    SPLICE_CYCLES = 15
    SCREEN_FLUSH = 500      # status screen flush time ms

    ERR_FMT = """
============= ERROR =============
{desc}
JS stacktrace:
  {stack}    
    """
    CRASH_FMT = """
============= CRASH ({type}) =============
{desc}
{operate}
{register}
    """
    TIMEOUT_FMT = """
============= TIMEOUT =============
{desc}
    """

    def __init__(self, **kwargs):
        super(Fuzz, self).__init__(**kwargs)

        self.pkg_name = kwargs.get('target')
        self.script_path = kwargs.get('script')
        self.seeds_dir = kwargs.get('seeds')
        self.output_dir = kwargs.get('output')

        # seeds
        self.initial = InitialSeeds()
        # queue
        self.queue = Queue(output=self.output_dir)
        # stats
        self.stats = FuzzStats()

        self.messages = 0

        self._init_()

    def _init_(self):
        if not self.pkg_name or \
                not os.path.isfile(self.script_path) or \
                not os.path.isdir(self.output_dir) or \
                not os.path.isdir(self.seeds_dir):
            raise ValueError

        for fn in os.listdir(self.seeds_dir):
            p = os.path.join(self.seeds_dir, fn)
            if os.path.isfile(p):
                self.initial.add(p)

        self.stats.target = self.pkg_name
        self.stats.output = self.output_dir
        cur_ms = get_cur_time()
        self.stats.start_time = cur_ms
        # self.stats.last_new_path = cur_ms
        self.stats.last_ms = cur_ms

        self.attach()

    def on_message(self, message, data):
        self.messages += 1
        if message['type'] == 'error':
            self.report_error(message)
            self.detach()

        msg = message['payload']
        if msg['event'] == 'clog':
            self.on_clog(msg, data)
            return

        if msg['event'] in ('stats', 'status'):
            self.on_stats(msg, data)
            return

        if msg['event'] == 'interesting':
            self.on_interesting(msg, data)
        # elif msg['event'] == 'next': # not used
        #    on_next(msg, data)
        elif msg['event'] == 'get':
            self.on_get(msg, data)
        elif msg['event'] == 'dry':
            self.on_dry(msg, data)
        elif msg['event'] == 'splice':
            self.on_splice(msg, data)
        elif msg['event'] in ('crash', 'exception'):
            self.on_crash(msg, data)
        elif msg['event'] == 'timeout':
            self.on_timeout(msg, data)
        else:
            logger.error('messages not support: {}'.format(msg))
            raise TypeError

        self.on_stats(msg, data)

    def saving(self, name, data):
        save_path = os.path.join(self.output_dir, name)
        with open(save_path, 'wb') as f:
            f.write(data)
        logger.info('saving at {}'.format(save_path))

    @staticmethod
    def on_clog(msg, data):
        d = msg.get('data', data)
        logger.info(' >> {}'.format(d))

    def on_interesting(self, message, data):
        self.stats.last_new_path = get_cur_time()
        self.stats.total_paths += 1

        exec_ms = message['exec_ms']
        new_cov = message['new_cov']
        stage = message['stage']['name']
        num = message['num']
        self.queue.add(data, exec_ms, new_cov, stage, num)

    def on_dry(self, message, data):
        seed = self.initial.get()
        if seed is None:
            self.script.post({
                'type': 'input',
                'buf': None,
            })
        else:
            logger.debug('Dry run {}'.format(seed))
            with open(seed, 'rb') as f:
                buf = f.read()
            self.script.post({
                'type': 'input',
                'num': self.initial.idx - 1,
                'buf': buf.hex(),
            })

    def on_get(self, message, data):
        num = message['num']
        q = self.queue.find_by_num(num)
        with open(q.filename, 'rb') as f:
            buf = f.read()
        self.script.post({
            'type': 'input',
            'num': q.num,
            'buf': buf.hex(),
        })

    def on_splice(self, message, data):
        num = message['num']
        splice_cycle = message['stage']['cycle']
        q = self.queue.find_by_num(num)
        with open(q.filename, 'rb') as f:
            buf = f.read()
        new_buf = None
        while splice_cycle < self.SPLICE_CYCLES:
            splice_cycle += 1
            new_buf = self.queue.get_splice_target(q, buf)
            if new_buf is not None:
                break
        if new_buf is None:
            self.script.post({
                'type': 'splice',
                'buf': None,  # failed
                'cycle': splice_cycle,
            })
        else:
            self.script.post({
                'type': 'splice',
                'buf': new_buf.hex(),
                'cycle': splice_cycle,
            })

    def on_crash(self, message, data):
        """ eg:
            {'event': 'crash', 'err': {'message': 'access violation accessing 0xdeadbeef', 'type': 'access-violation',
            'address': '0x71f95f89bc', 'memory': {'operation': 'write', 'address': '0xdeadbeef'},
            'context': {'pc': '0x71f95f89bc', 'sp': '0x72558e5e00', 'x0': '0x0', 'x1': '0x72e6b1f4d0',
            'x2': '0xa', 'x3': '0x5d5b667562004441', 'x4': '0x725a3110c7', 'x5': '0x72ea711325',
            'x6': '0x45443d5d5b667562', 'x7': '0x444145443d5d5b66', 'x8': '0xdeadbeef', 'x9': '0x1',
            'x10': '0x0', 'x11': '0x72558e5b74', 'x12': '0x3', 'x13': '0x10', 'x14': '0x72e6b1f40a',
            'x15': '0x72e6a59bd3', 'x16': '0x72e75a5170', 'x17': '0x72ebaf14b8', 'x18': '0x0',
            'x19': '0x4', 'x20': '0x725da0e050', 'x21': '0x72558e5f08', 'x22': '0x0', 'x23': '0x72558e5f30',
            'x24': '0x72560bf6b0', 'x25': '0x725cffd2b8', 'x26': '0x0', 'x27': '0x2', 'x28': '0x2',
            'fp': '0x72558e5e10', 'lr': '0x725a2edeec'},
            'nativeContext': '0x0', 'fileName': 'andff/template/native.js.tmp', 'lineNumber': 22},
            'stage': 'init', 'cur': -1, 'total_execs': 1, 'pending_fav': 0, 'favs': 0, 'map_rate': 5.46875}
        :param message:
        :param data:
        :return:
        """

        last_crash = self.stats.last_crash
        if not isinstance(last_crash, int):
            last_crash = self.stats.start_time
        self.stats.last_crash = get_cur_time() - last_crash
        self.stats.total_crashes += 1
        self.on_stats(message, data)

        crash_fmt = self.CRASH_FMT

        def register_fmt(rd: dict):
            fmt = ''
            i = 0
            for k, v in rd.items():
                i += 1
                fmt += '{}: {}'.format(
                    '{:3s}'.format(k),
                    '{:20s}'.format(v),
                )
                if i % 2 == 0:
                    fmt += '\n'

            return fmt

        type_, desc_, operate_, register_ = '', '', '', []

        err = message.get('err')
        if isinstance(err, dict):
            type_ = err.get('type')
            desc_ = err.get('message')
            memory = err.get('memory')
            if isinstance(memory, dict):
                operate_ = '{} at {}'.format(memory.get('operation'), memory.get('address'))

            ctx = err.get('context')
            if isinstance(ctx, dict):
                register_ = register_fmt(ctx)

        logger.error(
            crash_fmt.format(
                type=type_,
                desc=desc_,
                operate=operate_,
                register=register_
            )
        )

        name = 'crash_{}_{}_{}'.format(message['stage']['name'], type_, int(time.time()))
        self.saving(name, data)

        self.detach()

    def on_timeout(self, message, data):
        """
            if timeout (10s), set hang.
        :param message:
        :param data:
        :return:
        """
        last_hang = self.stats.last_hang
        if not isinstance(last_hang, int):
            last_hang = self.stats.start_time
        self.stats.last_hang = get_cur_time() - last_hang
        self.stats.total_hangs += 1

        except_fmt = self.TIMEOUT_FMT
        desc_, stage_ = message['err'], message['stage']
        logger.warning(
            except_fmt.format(
                desc=desc_
            )
        )

        name = 'hang_{}_{}'.format(stage_.get('name'), int(time.time()))
        self.saving(name, data)

        # self.detach()

    def report_error(self, message):
        err_fmt = self.ERR_FMT
        line = message.get('lineNumber')
        if not line:
            desc = message['description']
        else:
            desc = 'line {}: {}'.format(line, message['description'])

        stack = message.get('stack', '')
        logger.error(err_fmt.format(desc=desc, stack=stack))

    def on_stats(self, message, data):
        from .afl import afl_print

        cur_ms = get_cur_time()
        if cur_ms - self.stats.last_ms < self.SCREEN_FLUSH:
            return

        # average speed
        stages = message['stage']
        stage_name, stage_cur, stage_max, total_execs = \
            stages.get('name', '<init>'), stages.get('cur', 0), stages.get('max', 0), stages.get('total_execs', 0)
        queue = message['queue']
        cur_idx, pending_fav, favs, queue_cycle = \
            queue.get('cur_idx', 0), queue.get('pending_fav', 0), queue.get('favs', 0), queue.get('queue_cycle', 0)

        eps_total = float(total_execs) * 1000 / (cur_ms - self.stats.start_time)
        if not self.stats.last_execs:
            self.stats.exec_speed = eps_total
        else:
            cur_eps = float(total_execs - self.stats.last_execs) * 1000 / (cur_ms - self.stats.last_ms)
            if cur_eps * 5 < self.stats.exec_speed or cur_eps / 5 > self.stats.exec_speed:
                self.stats.exec_speed = cur_eps
            self.stats.exec_speed = self.stats.exec_speed * (1.0 - 1.0 / 16) + cur_eps * (1.0 / 16)

        self.stats.last_execs = total_execs
        self.stats.last_ms = cur_ms
        self.stats.run_time = cur_ms - self.stats.start_time
        self.stats.total_execs = total_execs
        self.stats.current_stage = stage_name
        self.stats.stage_execs = [stage_cur, stage_max]
        self.stats.queue_size = [cur_idx + 1, self.queue.max_num + 1]
        self.stats.favored_paths = favs
        self.stats.pend_fav = pending_fav
        self.stats.queue_cycle = queue_cycle
        self.stats.map_density = message.get('map_rate')

        cps = copy.copy(self.stats)
        cps.exec_speed = '{}/sec'.format(int(cps.exec_speed)),
        cps.run_time = readable_time(cps.run_time)
        if cps.total_paths > 0:
            cps.last_new_path = readable_time(cur_ms - cps.last_new_path)
            cps.favored_paths = '{} ({})'.format(
                cps.favored_paths,
                '{0:.2f}%'.format(float(cps.favored_paths * 100)/cps.total_paths)
            )
        cps.last_crash = readable_time(cps.last_crash)
        cps.last_hang = readable_time(cps.last_hang)
        cps.map_density = '{0:.2f} %'.format(cps.map_density)
        if stage_max > 0:
            cps.stage_execs = '{}/{} ({})'.format(
                stage_cur, stage_max,
                '{0:.2f}%'.format(float(stage_cur * 100) / stage_max)
            )
        else:
            cps.stage_execs = '0/0 (0.00%)'
        cps.queue_size = '{}/{} ({})'.format(
            cps.queue_size[0], cps.queue_size[1],
            '{0:.2f}%'.format(float(cps.queue_size[0] * 100) / cps.queue_size[1])
        )
        # print(self.stats.__dict__)

        afl_print(
           **cps.__dict__
        )
