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

# EL OBJETO REPOSITORIO
# El objeto repositorio representa un repositorio de Git.


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

# EL COMANDO INIT


argsp = argsubparsers.add_parser(
    "init", help="Inicia un nuevo reporsitorio vacío")

argsp.add_argument("path",
                   metavar="directorio",
                   nargs="?",
                   default=".",
                   help="Donde crear el repositorio.")


def cmd_init(*args):
    repo_create(args.path)

# LA FUNCIÓN repo_find()


def repo_find(path=".", required=True):
    path = os.path.realpath(path)

    if os.path.isdir(os.path.join(path, ".git")):
        return GitRepository(path)

    parent = os.path.realpath(os.path.join(path, ".."))

    if parent == path:
        if required:
            raise Exception("No se encontró el repositorio")
        else:
            return None

    return repo_find(parent, required)

# LA CLASE OBJECT


class GitObject(object):
    """Representa un objeto de Git"""

    def __init__(self, data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init()

    def serialize(self, repo):
        """Esta función DEBE ser implementada por las sublcases

        debe leer el contenido del objeto de self.data, la cadena d bytes y hacer
        lo que sea necesario para convertirlo en una representación significativa
        """

        raise Exception("No implementada!")

    def deserialize(self, data):
        raise Exception("No implementada!")

    def init(self):
        pass


def object_read(repo, sha):
    """Lee un objeto de Git a partir de su SHA-1
    Devuelve un GitObject que su tipo depende del objeto"""

    path = repo_file(repo, "objects", sha[0:2], sha[2:])

    if not os.path.isfile(path):
        return None

    with open(path, "rb") as f:
        raw = zlib.decompress(f.read())

        # Lee el tipo de objeto
        x = raw.find(b" ")
        fmt = raw[0:x]

        # Lee y valida el tamaño del objeto
        y = raw.find(b"\x00", x)
        size = int(raw[x:y].decode("ascii"))
        if size != len(raw)-y-1:
            raise Exception(f"Error de tamaño en el objeto {sha}")

        # Elige el constructor adecuado
        match fmt:
            case b"commit": c = GitCommit
            case b"tree": c = GitTree
            case b"tag": c = GitTag
            case b"blob": c = GitBlob
            case _:
                raise Exception(
                    f"Tipo desconocido {fmt.decode('ascii')} para el objeto {sha}")

        # Llama al constructor y devuelve el objeto
        return c(raw[y+1:])


def object_write(obj, repo=None):
    # serializa los datos del objeto
    data = obj.serialize()
    # agrega el encabezado
    result = obj.fmt + b" " + str(len(data)).encode() + b"\x00" + data
    # calcula el hash
    sha = hashlib.sha1(result).hexdigest()

    if repo:
        # calcula la ruta
        path = repo_file(repo, "objects", sha[0:2], sha[2:], mkdir=True)

        if not os.path.exists(path):
            with open(path, "wb") as f:
                # comprime y escribe el objeto
                f.write(zlib.compress(result))
    return sha


class GitBlob(GitObject):
    fmt = b"blob"

    def serialize(self):
        return self.blobdata

    def deserialize(self, data):
        self.blobdata = data

# EL COMANDO cat-file


argsp = argsubparsers.add_parser("cat-file",
                                 help="Muestra contenido de los objetos del repositorio")

argsp.add_argument("type",
                   metavar="type",
                   choices=["blob", "commit", "tag", "tree"],
                   help="Especifica el tipo de objeto")

argsp.add_argument("object",
                   metavar="object",
                   help="El objeto a mostrar")


def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())


def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, object_find(repo, obj, fmt=fmt))
    sys.stdout.buffer.write(obj.serialize())


def object_find(repo, name, fmt=None, follow=True):
    return name


argsp = argsubparsers.add_parser("hash-object",
                                 help="Calcula el ID de un objeto y crea un "
                                 "blob de un archivo")

argsp.add_argument("-t",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default="blob",
                   help="Especifica el tipo de objeto")

argsp.add_argument("-w",
                   dest="write",
                   action="store_true",
                   help="Escribe el objeto dentro de la base de datos")

argsp.add_argument("path",
                   help="Lee el archivo desde <file>")


def fcmd_hash_object(args):
    if args.write:
        repo = repo_find()
    else:
        repo = None

    with open(args.path, "rb") as fd:
        sha = object_hash(fd, args.type.encode(), repo)
        print(sha)


def object_hash(fd, fmt, repor=None):
    """Objeto hash, escrito en el repo si se provee"""
    data = fd.read()

    # Elige el constructor de acuerdo al argumento fmt
    match fmt:
        case b"commit": obj = GitCommit(data)
        case b"tree": obj = GitTree(data)
        case b"tag": obj = GitTag(data)
        case b"blob": obj = GitBlob(data)
        case _ = rasie Exception(f"Tipo desconocido {fmt}!")

    return object_write(obj, repo)

# ANALIZAR COMMITS


def kvlm_parse(raw, start=0, dct=None):
    if not dct:
        dct = dict()

    spc = raw.find(b" ", start)
    nl = raw.find(b"\n", start)

    if (spc < 0) or (nl < spc):
        assert nl == start
        dct[None] = raw[start+1:]
        return dct

    key = raw[start:spc]

    end = start
    while True:
        end = raw.find(b"\n", end+1)
        if raw[end+1] != ord(b" "):
            break

    value = raw[spc+1:end].replace(b"\n ", b"\n")

    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(value)
        else:
            dct[key] = [dct[key], value]
    else:
        dct[key] = value
    return kvlm_parse(raw, start=end+1, dct=dct)


def kvlm_serialize(kvlm):
    ret = b""

    for k in kvlm.keys():
        if k == None:
            continue
        val = kvlm[k]
        if type(val) != list:
            val = [val]

        for v in val:
            ret += k+b" "+(v.replace(b"\n", b"\n ")) + b"\n"
    ret += b"\n" + kvlm[None]

    return ret

# EL OBJETO COMMIT


class GitCommit(GitObject):
    fmt = b"commit"

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self, repo):
        return kvlm_serialize(self.kvlm)

    def init(self):
        self.kvlm = dict()

# El COMANDO log


argsp = argsubparsers.add_parser("log",
                                 help="Muestra el historial de commits")
argsp.add_argument("commit",
                   default="HEAD",
                   nargs="?",
                   help="Commit a partir del cual se inicia la visualización")


def cmd_log(args):
    repo = repo_find()

    print("digraph wyaglog{")
    print(" node [shape=rect]")
    log_graphviz(repo, object_find(repo, args.commit), set())
    print("}")


def log_graphviz(repo, sha, seen):
    if sha in seen:
        return
    seen.add(sha)

    commit = object_read(repo, sha)
    message = commit.kvlm[None].decode("utf-8").strip()
    message = message.replace("\\", "\\\\")
    message = message.replace('\"', '\\\"')

    if "\n" in message:
        message = message[:message.index("\n")]

    print(f" c_{sha} [label=\" {sha[0:7]}: {message}\"]")
    assert commit.fmt == b"commit"

    if not b"parent" in commit.kvlm.keys():
        return

    parents = commit.kvlm[b"parent"]

    if type(parents) != list:
        parents = [parents]

    for p in parents:
        p = p.decode("ascii")
        print(f" c_{sha} -> c_{p};")
        log_graphviz(repo, p, seen)

# ANALIZAR TREES


class GitTreeLeaf(object):
    def __init__(self, mode, path, sha):
        self.mode = mode
        self.path = path
        self.sha = sha


def tree_parse_one(raw, start=0):
    x = raw.find(b" ", start)
    assert x-start == 5 or x-start == 6

    mode = raw[start:x]
    if len(mode) == 5:
        mode = b"0" + mode

    y = raw.find(b"\x00", x)
    path = raw[x+1:y]

    raw_sha = int.from_bytes(raw[y+1:y+21], "big")
    sha = format(raw_sha, "040x")
    return y+21, GitTreeLeaf(mode, path.decode("utf-8"), sha)


def tree_parse(raw):
    pos = 0
    max = len(raw)
    ret = list()
    while pos < max:
        pos, data = tree_parse_one(raw, pos)
        ret.append(data)
    return ret


def tree_leaf_sort_key(leaf):
    if leaf.mode.startswith(b"10"):
        return leaf.path
    else:
        return leaf.path + "/"


def tree_serialize(obj):
    obj.items.sort(key=tree_leaf_sort_key)
    ret = b""
    for i in obj.items:
        ret += i.mode
        ret += b" "
        ret += i.path.encode("utf-8")
        ret += b"\x00"
        sha = int(i.sha, 16)
        ret += sha.to_bytes(20, byteorder="big")
    return ret


class GitTree(GitObject):
    fmt = b"tree"

    def deserialize(self, data):
        self.items = tree_parse(data)

    def serialize(self):
        return tree_serialize(self)

    def init(self):
        self.items = list()

# EL COMANDO ls-tree


argsp = argsubparsers.add_parser("ls-tree",
                                 help="Muestra el contenido de un árbol")
argsp.add_argument("-r",
                   dest="recursive",
                   action="store_true",
                   help="Muestra el contenido de los subárboles")
argsp.add_argument("tree",
                   help="El árbol a mostrar")


def cmd_ls_tree(args):
    repo = repo_find()
    ls_tree(repo, args.tree, args.recursive)


def ls_tree(repo, ref, recursive=None, prefix=""):
    sha = object_find(repo, ref, fmt=b"tree")
    obj = object_read(repo, sha)
    for item in obj.items:
        if len(item.mode) == 5:
            type == item.mode[0:1]
        else:
            type = item.mode[0:2]

        match type:  # Determina el tipo
            case b"04": type = "tree"
            case b"10": type = "blob"  # Un archivo regular
            case b"12": type = "blob"  # Un archivo simbólico
            case b"16": type = "commit"  # Un submódulo
            case _: raise Exception(f"Tipo desconocido {item.mode}")

        if not (recursive and type == "tree"):
            print(f"{'0' * (6 - len(item.mode)) + item.mode.decode('ascii')} {type} {item.sha}\t{os.path.join(prefix, item.path)}")
        else:
            ls_tree(repo, item.sha, recursive, os.path.join(prefix, item.path))
