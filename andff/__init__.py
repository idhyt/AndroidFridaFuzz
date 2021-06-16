import sys
from .implement.interface import fri_compile, fri_fuzz


def call_compile(*args):
    return fri_compile(config=args[0])


def call_fuzz(*args):
    return fri_fuzz(config=args[0])


def caller():
    functions = {
        '--compile': call_compile,
        '--fuzz': call_fuzz
    }

    def usage():
        sys.stderr.write('supported arguments:')
        sys.stderr.write('\n\t')
        sys.stderr.write('\n\t'.join(sorted(functions.keys())))
        sys.stderr.write('\n')
        sys.stderr.write('eg: python fuzz.py --compile ./config.json\n')
        raise SystemExit(1)

    if len(sys.argv) == 1:
        usage()

    sys.argv.pop(0)
    name = sys.argv[0]
    call_function = functions.get(name, None)
    sys.argv.pop(0)
    if not call_function:
        usage()

    call_function(*sys.argv)
