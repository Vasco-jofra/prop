from .color import *


def print_head(msg):
    print GREEN + msg + ":" + NO_COLOR


def print_opt(nr, msg):
    print "[" + YELLOW + str(nr) + NO_COLOR + "] " + msg


def log_fatal(fatal_msg):
    print "[" + RED + "FATAL" + NO_COLOR + "] " + fatal_msg
    print "Exiting..."
    exit(-1)


def log_error(error_msg):
    print "[" + RED + "ERROR" + NO_COLOR + "] " + error_msg


def log_warn(warn_msg):
    print "[" + YELLOW_BOLD + "WARN" + NO_COLOR + "] " + warn_msg


def log_info(info_msg):
    print "[" + BLUE + "INFO" + NO_COLOR + "] " + info_msg


def log_debug(debug_msg):
    print "[" + RED + "DEBUG" + NO_COLOR + "] " + debug_msg
