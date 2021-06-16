# -*- coding: UTF-8 -*-

"""
    see https://github.com/google/AFL/blob/master/debug.h

"""

FANCY_BOXES = True

cBLK = "\x1b[0;30m"
cRED = "\x1b[0;31m"
cGRN = "\x1b[0;32m"
cBRN = "\x1b[0;33m"
cBLU = "\x1b[0;34m"
cMGN = "\x1b[0;35m"
cCYA = "\x1b[0;36m"
cLGR = "\x1b[0;37m"
cGRA = "\x1b[1;90m"
cLRD = "\x1b[1;91m"
cLGN = "\x1b[1;92m"
cYEL = "\x1b[1;93m"
cLBL = "\x1b[1;94m"
cPIN = "\x1b[1;95m"
cLCY = "\x1b[1;96m"
cBRI = "\x1b[1;97m"
cRST = "\x1b[0m"

bgBLK = "\x1b[40m"
bgRED = "\x1b[41m"
bgGRN = "\x1b[42m"
bgBRN = "\x1b[43m"
bgBLU = "\x1b[44m"
bgMGN = "\x1b[45m"
bgCYA = "\x1b[46m"
bgLGR = "\x1b[47m"
bgGRA = "\x1b[100m"
bgLRD = "\x1b[101m"
bgLGN = "\x1b[102m"
bgYEL = "\x1b[103m"
bgLBL = "\x1b[104m"
bgPIN = "\x1b[105m"
bgLCY = "\x1b[106m"
bgBRI = "\x1b[107m"

if FANCY_BOXES:
    SET_G1 = "\x1b)0"       # Set G1 for box drawing
    RESET_G1 = "\x1b)B"     # Reset G1 to ASCII
    bSTART = "\x0e"         # Enter G1 drawing mode
    bSTOP = "\x0f"          # Leave G1 drawing mode
    bH = "q"                # Horizontal line
    bV = "x"                # Vertical line
    bLT = "l"               # Left top corner
    bRT = "k"               # Right top corner
    bLB = "m"               # Left bottom corner
    bRB = "j"               # Right bottom corner
    bX = "n"                # Cross
    bVR = "t"               # Vertical, branch right
    bVL = "u"               # Vertical, branch left
    bHT = "v"               # Horizontal, branch top
    bHB = "w"               # Horizontal, branch bottom
else:
    SET_G1 = ""
    RESET_G1 = ""
    bSTART = ""
    bSTOP = ""
    bH = "-"
    bV = "|"
    bLT = "+"
    bRT = "+"
    bLB = "+"
    bRB = "+"
    bX = "+"
    bVR = "+"
    bVL = "+"
    bHT = "+"
    bHB = "+"

TERM_HOME = "\x1b[H"
TERM_CLEAR = TERM_HOME + "\x1b[2J"
cEOL = "\x1b[0K"
CURSOR_HIDE = "\x1b[?25l"
CURSOR_SHOW = "\x1b[?25h"

bSTG = bSTART + cMGN  # cGRA
bH2 = bH + bH
bH5 = bH2 + bH2 + bH
bH10 = bH5 + bH5
bH20 = bH10 + bH10
bH30 = bH20 + bH10
SP5 = "     "
SP10 = SP5 + SP5
SP20 = SP10 + SP10

_CLEAR_SCREEN = True


# Just print stuff to the appropriate stream
def SAYF(*args):
    print(''.join(args))


def check_term_size():
    import os
    row, col = os.popen('stty size', 'r').read().split()
    if int(row) < 25 or int(col) < 80:
        SAYF(cBRI, 'Your terminal {}x{} is too small to display the UI.\n'.format(col, row),
             'Please resize terminal window to at least 80x25.\n', cRST)
        return False
    return True


def afl_print(**kwargs):
    global _CLEAR_SCREEN
    if _CLEAR_SCREEN:
        SAYF(TERM_CLEAR)
        SAYF(CURSOR_HIDE)
        _CLEAR_SCREEN = False

    SAYF(TERM_HOME)

    if not check_term_size():
        _CLEAR_SCREEN = True
        return

    target = kwargs.get('target', 'com.example.demo')
    output = kwargs.get('output', './')[-60:]

    run_time = kwargs.get('run_time', '0 days, 0 hrs, 0 min, 0 sec ')
    cycles_done = kwargs.get('queue_cycle', '0')
    last_new_path = kwargs.get('last_new_path', '0 days, 0 hrs, 0 min, 0 sec ')
    total_paths = kwargs.get('total_paths', '0')
    last_crash = kwargs.get('last_crash', 'none seen yet ')
    last_hang = kwargs.get('last_hang', 'none seen yet ')
    total_hangs = kwargs.get('total_hangs', '0')

    # now_processing = kwargs.get('now_processing', '0 (0.00%)')
    queue_size = kwargs.get('queue_size', '0')
    map_density = kwargs.get('map_density', '0.00%')

    current_stage = kwargs.get('current_stage', '<init>')
    favored_paths = kwargs.get('favored_paths', '0')
    stage_execs = kwargs.get('stage_execs', '0')
    total_execs = kwargs.get('total_execs', '0')
    total_crashes = kwargs.get('total_crashes', '0')
    exec_speed = kwargs.get('exec_speed', '0/sec')

    havoc = kwargs.get('havoc', '0/0k, 0/0')
    pend_fav = kwargs.get('pend_fav', '0')

    SAYF(SP20, cGRN, 'Android Frida Fuzz', '({})'.format(target))

    # SAYF(bLB, bSTG, bH30, bH20, bH2, bH2, bH20, bH2 * 2, bLB)
    # SAYF(bV, bSTOP, " fuzz target : ", cRST, "%-62s " % target, bSTG, bV, bSTOP)
    # SAYF(bV, bSTOP, " fuzz output : ", cRST, "%-62s " % output, bSTG, bV, bSTOP)

    SAYF(SET_G1, bSTG, bLT, bH, bSTOP, cCYA,
         " process timing ",
         bSTG, bH30, bH5, bH2, bHB, bH, bSTOP, cCYA,
         " overall results ",
         bSTG, bH5, bRT)

    # used time
    SAYF(bV, bSTOP,
         "        run time : ", cRST, "%-34s " % run_time,
         bSTG, bV, bSTOP,
         "  cycles done : ", cRST, "%-6s " % cycles_done, bSTG, bV)

    # new paths
    SAYF(bV, bSTOP, "   last new path : ", cRST, "%-34s " % last_new_path,
         bSTG, bV, bSTOP,
         "  total paths : ", cRST, "%-6s " % total_paths, bSTG, bV)

    # crash
    SAYF(bV, bSTOP, " last uniq crash : ", cRST, "%-34s " % last_crash,
         bSTG, bV, bSTOP,
         " uniq crashes : ", cRST, "%-6s " % total_crashes, bSTG, bV)

    # exception
    SAYF(bV, bSTOP, "  last uniq hang : ", cRST, "%-34s " % last_hang, bSTG, bV, bSTOP,
         "   uniq hangs : ", cRST, "%-6s " % total_hangs, bSTG, bV)

    SAYF(bVR, bH, bSTOP, cCYA, " cycle progress ", bSTG, bH20, bHB, bH, bSTOP,
         cCYA, " map coverage ", bSTG, bH, bHT, bH20, bH2, bH, bVL)

    # SAYF(bV, bSTOP, "  now processing : ", cRST, "%-17s " % now_processing, bSTG, bV, bSTOP,
    #      "   map density : ", cRST, "%-22s " % map_density, bSTG, bV)

    SAYF(bV, bSTOP, "  now processing : ", cRST, "%-17s " % queue_size, bSTG, bV, bSTOP,
         "   map density : ", cRST, "%-22s " % map_density, bSTG, bV)

    SAYF(bVR, bH, bSTOP, cCYA, " stage progress ", bSTG, bH20, bX, bH, bSTOP,
         cCYA, " findings in depth ", bSTG, bH20, bVL)

    # stage_name, favoreds
    SAYF(bV, bSTOP, "  now trying : ", cRST, "%-21s " % current_stage, bSTG, bV, bSTOP,
         " favored paths : ", cRST, "%-22s " % favored_paths, bSTG, bV)

    SAYF(bV, bSTOP, " stage execs : ", cRST, "%-21s " % stage_execs, bSTG, bV, bSTOP,
         SP20 * 2, bSTG, bV)

    SAYF(bV, bSTOP, " total execs : ", cRST, "%-21s " % total_execs, bSTG, bV, bSTOP,
         " total crashes : ", cLRD if int(total_crashes) > 0 else cRST, "%-22s " % total_crashes, bSTG, bV)

    SAYF(bV, bSTOP, "  exec speed : ", cRST, "%-21s " % exec_speed, bSTG, bV, bSTOP,
         SP20 * 2, bSTG, bV)

    SAYF(bVR, bH, cCYA, bSTOP, " fuzzing strategy yields ", bSTG, bH10, bH, bHT, bH10,
         bH5, bHB, bH, bSTOP, cCYA, " path geometry ", bSTG, bH5, bH2, bH, bVL)

    SAYF(bV, bSTOP, "       havoc : ", cRST, "%-37s " % havoc, bSTG, bV, bSTOP,
         "  pend fav : ", cRST, "%-10s " % pend_fav, bSTG, bV)

    SAYF(bLB, bSTG, bH30, bH20, bH2, bH, bHT, bH20, bH2 * 2, bRB)

    SAYF(RESET_G1)

    print('', flush=True)


if __name__ == '__main__':
    import time
    import random

    t = 0
    while True:
        afl_print(
            cycles_done=random.randint(0, 100),
            total_paths=random.randint(0, 100),
            total_crashes=random.randint(0, 10),
            exec_speed='{}/sec'.format(random.randint(0, 1000)),
            total_execs=random.randint(100, 10000),
            run_time='0 days 0 hrs, 0 min, {} sec '.format(t)
        )
        time.sleep(1)
        t += 1
