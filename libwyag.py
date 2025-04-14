import argparse
import configparser
from datetime import datetime
import grp
import pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import zlib

argparse = argparse.ArgumentParser(
    description="Un seguidor de contenido de los Chinos")
argsubparsers = argparse.add_subparsers(title="Comandos", dest="comando")
