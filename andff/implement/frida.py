import sys
import frida
from .logger import def_logger as logger


class Frida(object):
    def __init__(self, **kwargs):
        self.pkg_name = kwargs.get('pkg_name')
        self.script_file = kwargs.get('script')

        self._script = None
        self._session = None

    @property
    def script(self):
        if not self._script:
            self.attach()
        return self._script

    @property
    def session(self):
        if not self._session:
            self.attach()
        return self._session

    def attach(self):
        device = frida.get_usb_device()
        self._session = device.attach(self.pkg_name)
        with open(self.script_file) as f:
            code = f.read()
        self._script = self.session.create_script(code)

        self._script.on('message', self.on_message)
        self._script.load()

    def detach(self):
        try:
            self.script.unload()
            self.session.detach()
        except Exception as e:
            logger.error(e)

    def run(self):
        try:
            self.script.exports.loop()
            sys.stdin.read()
        except (frida.core.RPCException, frida.InvalidOperationError) as e:
            logger.error('fri exception. {}'.format(e))
        except Exception as e:
            logger.error(e)

    def on_message(self, message, data):
        logger.debug('message: {}, data: {}'.format(message, data))
