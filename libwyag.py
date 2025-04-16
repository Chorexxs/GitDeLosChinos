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


def main(argv=sys.argv[1:]):
    args = argparse.parse_args(argv)
    match args.comando:
        case "add": cmd_add(args)
        case "cat-file": cmd_cat_file(args)
        case "check-ignore": cmd_check_ignore(args)
        case "checkout": cmd_checkout(args)
        case "commit": cmd_commit(args)
        case "hash-object": cmd_hash_object(args)
        case "init": cmd_init(args)
        case "log": cmd_log(args)
        case "ls-files": cmd_ls_files(args)
        case "ls-tree": cmd_ls_tree(args)
        case "rev-parse": cmd_rev_parse(args)
        case "rm": cmd_rm(args)
        case "show-ref": cmd_show_ref(args)
        case "status": cmd_status(args)
        case "tag": cmd_tag(args)
        case _: print("Comando no válido")


class GitRepository(object):
    """Representa un repositorio de Git."""

    worktree = None
    gitdir = None
    conf = None

    def __init__(self, path, force=False):
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")

        if not (force or os.path.isdir(self.gitdir)):
            raise Exception(f"No es un repositorio de Git válido: {path}")

    # Lee el archivo de configuración en .git/config
    self.conf = configparser.ConfigParser()
    cf = repo_file(self, "config")

    if cf and os.path.exists(cf):
        self, conf.read([cf])
    elif not force:
        raise Exception("Archivo de configuración no encontrado")

    if not force:
        vers = int(self.conf.get("core", "repositoryformatversion"))
        if vers != 0:
            raise Exception(
                f"Versión de formato de repositorio no soportada: {vers}")


def repo_path(repo, *path):
    """Calcula la ruta absoluta de un archivo en el repositorio."""
    return os.path.join(repo.gitdir, *path)


def repo_file(repo, *path, mkdir=False):
    """Lo mismo que repo_path, pero crea el directorio *path si no existe."""

    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)


def repo_dir(repo, *path, mkdir=False):
    """Lo mismo que repo_path, pero para directorios."""

    path = repo_path(repo, *path)

    if os.path.exists(path):
        if (os.path.isdir(path)):
            return path
        else:
            raise Exception(f"No es un directorio {path}")

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None


def repo_create(path):
    """Crea un nuevo repositorio en path."""

    repo = GitRepository(path, True)

    # Primero se asegura que el path o no existe o es un dir vacío

    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception(f"{path} no es un directorio")
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception(f"{path} no es un directorio vacío")
    else:
        os.makedirs(repo.worktree)

    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)

    # .git/description es un archivo de texto que describe el repositorio
    with open(repo_file(repo, "descripción"), "w") as f:
        f.write(
            "repositorio sin nombre; edita el archivo 'descripción' para cambiarlo\n")

    # .git/HEAD es un archivo de texto que contiene la referencia a la rama actual
    with open(repo_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")

    with open(repo_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)

    return repo


def repo_default_config():
    """Devuelve la configuración por defecto del repositorio."""
    ret = configparser.ConfigParser()

    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "fasle")
    ret.set("core", "bare", "false")

    return ret
