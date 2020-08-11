from .logger import *
import os
import shutil


def get_file_content(file_name):
    if os.path.isfile(file_name) == False:
        log_fatal("Unable to get the contents of the file '%s'" % file_name)

    res = ""
    with open(file_name, "r") as f:
        res = f.read()
    return res


def copy_file(dst, src):
    # Sanaty checks
    if os.path.exists(dst):
        log_fatal("File '%s' already exists. Please remove it or rename it." % dst)

    if os.path.exists(src) == False:
        log_fatal("Missing file '%s'." % src)

    # Actually copy
    log_info("Copying '%s' to '%s'" % (src, dst))
    shutil.copy(src, dst)
