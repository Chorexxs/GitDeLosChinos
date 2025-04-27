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

# EL COMANDO checkout


argsp = argsubparsers.add_parser("checkout",
                                 help="Checkout de un commit dentro de un directorio")

argsp.add_argument("commit",
                   help="El commit o tree a hacer checkout")

argsp.add_argument("path",
                   help="El directorio vacío donde hacer el checkout")


def cmd_checkout(args):
    repo = repo_find()

    obj = object_read(repo, object_find(repo, args.commit))

    # Si el objeto es un commit, botiene el tree
    if obj.fmt == b"commit":
        obj = object_read(repo, obj.kvlm[b"tree"].decode("ascii"))

    # Verifica que el path sea un directorio vacío
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception(f"{args.path} no es un directorio")
        if os.listdir(args.path):
            raise Exception(f"{args.path} no es un directorio vacío")
    else:
        os.makedirs(args.path)

    tree_checkout(repo, obj, os.path.realpath(args.path))


def tree_checkout(repo, tree, path):
    for item in tree.items:
        obj = object_read(repo, item.sha)
        dest = os.path.join(path, item.path)

        if obj.fmt == b"tree":
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif obj.fmt == b"blob":
            # Soporta symlinks
            with open(dest, "wb") as f:
                f.write(obj.blobdata)

# EL COMANDO show-ref


def ref_resolve(repo, ref):
    path = repo_file(repo, ref)

    if not os.path.isfile(path):
        return None

    with open(path, "r") as fp:
        data = fp.read()[:-1]
    if data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data


def ref_list(repo, path=None):
    if not path:
        path = repo_dir(repo, "refs")
    ret = dict()
    # Ordenar los refs que se muestran
    for f in sorted(os.listdir(path)):
        can = os.path.join(path, f)
        if os.path.isdir(can):
            ret[f] = ref_list(repo, can)
        else:
            ret[f] = ref_resolve(repo, can)
    return ret


argsp = argsubparsers.add_parser("show-ref",
                                 help="Muestra la lista de refs")


def show_ref(repo, refs, with_hash=True, prefix=""):
    if prefix:
        prefix = prefix + "/"
    for k, v in refs.items():
        if type(v) == str and with_hash:
            print(f"{v} {prefix}{k}")
        elif type(v) == str:
            print(f"{prefix}{k}")
        else:
            show_ref(repo, v, with_hash=with_hash, prefix=f"{prefix}{k}")

# Tag ligeras, objetos de tag y analisis de tags


class GitTag(GitCommit):
    fmt = b"tag"

# EL COMANDO tag

# git tag -> Enlista todos los tags
# git tag NAME [OBJECT] -> Crea un tag ligero
# git tag -a NAME [OBJECT] -> Crea un tag *objeto*


argsp = argsubparsers.add_parser("tag",
                                 help="Crea y enlista tags")

argsp.add_argument("-a",
                   action="store_true",
                   dest="create_tag_object",
                   help="Crea un objeto de tag")

argsp.add_argument("name",
                   nargs="?",
                   help="Nombre del tag que se va a crear")

argsp.add_argument("object",
                   default="HEAD",
                   nargs="?",
                   help="El objeto al que se le asigna el tag")


def cmd_tag(args):
    repo = repo_find()

    if args.name:
        tag_create(repo,
                   args.name,
                   args.object,
                   create_tag_object=args.create_tag_object)
    else:
        refs = ref_list(repo)
        show_ref(repo, refs["tags"], with_hash=False)


def tag_create(repo, name, ref, create_tag_object=False):
    # Obtiene el GitObject de la referencia
    sha = object_find(repo, ref)

    if create_tag_object:
        # Crea el objeto de tag
        tag = GitTag()
        tag.kvlm = dict()
        tag.kvlm[b"object"] = sha.encode()
        tag.kvlm[b"type"] = b"commit"
        tag.kvlm[b"tag"] = name.encode()

        tag.kvlm[b"tagger"] = b"wyaf <wyag@ejemplo.com>"
        tag.kvlm[None] = b"Tag creado por wyag"
        tag_sha = object_write(tag, repo)
        ref_create(repo, "tags/" + name, tag_sha)
    else:
        ref_create(repo, "tags/" + name, sha)


def ref_create(repo, ref_name, sha):
    with open(repo_file(repo, "refs/" + ref_name), "w") as fp:
        fp.write(sha + "\n")

# LA FUNCIÓN object_find


def object_resolve(repo, name):
    """Resuelve un nombre a un objeto hash."""
    candidates = list()
    hashRE = re.compile(r"^[0-9A-Fa-f]{4,40}$")

    if not name.strip:
        return None

    if name == "HEAD":
        return [ref_resolve(repo, "HEAD")]

    if hashRE.match(name):
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            rem = name[2:]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix + f)

    as_tag = ref_resolve(repo, "refs/tags/" + name)
    if as_tag:
        candidates.append(as_tag)

    as_branch = ref_resolve(repo, "refs/heads/" + name)
    if as_branch:
        candidates.append(as_branch)

    return candidates


def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)

    if not sha:
        raise Exception(f"Referencia no válida: {name}")

    if len(sha) > 1:
        raise Exception(
            f"Referencia ambigua {name}: Los candidatos son:\r - {'\n - '.join(sha)}.")

    sha = sha[0]

    if not fmt:
        return sha

    while True:
        obj = object_read(repo, sha)

        if obj.fmt == fmt:
            return sha

        if not follow:
            return None

        if obj.fmt == b"tag":
            sha = obj.kvlm[b"object"].decode("ascii")
        elif obj.fmt == b"commit" and fmt == b"tree":
            sha = obj.kvlm[b"tree"].decode("ascii")
        else:
            return None

# EL COMANDO rev-parse


argsp = argsubparsers.add_parser("rev-parse",
                                 help="Analizar identificadores de revisiones (u otros objetos)")

argsp.add_argument("--wyaf-type",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default=None,
                   help="Especifica el tipo de objeto")

argsp.add_argument("name",
                   help="El objeto a analizar")


def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None

    repo = repo_find()

    print(object_find(repo, args.name, fmt, follow=True))

# ANALIZAR EL INDEX


class GitIndexEntry(object):
    def __init__(self, ctime=None, mtime=None, dev=None, ino=None,
                 mode_type=None, mode_perms=None, uid=None, gid=None,
                 fsize=None, sha=None, flag_assume_valid=None,
                 flag_stage=None, name=None):
        # La ultima modificación de los metadatos del archivo
        self.ctime = ctime
        # La ultima modificación de los datos del archivo
        self.mtime = mtime
        # El ID del dispositivo
        self.dev = dev
        # El número de inodo
        self.ino = ino
        # El tipo de objeto. b1000 (regular), b1010 (symlink), b1100 (gitlink)
        self.mode_type = mode_type
        # Los permisos del objeto
        self.mode_perms = mode_perms
        # El ID del propietario
        self.uid = uid
        # El ID del grupo
        self.gid = gid
        # El tamaño del objeto, en bytes
        self.fsize = fsize
        # El SHA-1 del objeto
        self.sha = sha
        self.flag_assume_valid = flag_assume_valid
        self.flag_stage = flag_stage
        # El nombre del objeto (el path completo)
        self.name = name


class GitIndex(object):
    version = None
    entries = []

    def __init__(self, version=2, entries=None):
        if not entries:
            entries = []

        self.version = version
        self.entries = entries


def index_read(repo):
    index_file = repo_file(repo, "index")

    if not os.path.exists(index_file):
        return GitIndex()

    with open(index_file, "rb") as f:
        raw = f.read()

    header = raw[:12]
    signature = header[:4]
    assert signature == b"DIRC"  # Significa "DirCache"
    version = int.from_bytes(header[4:8], "big")
    assert version == 2, "wyag sólo soporta la versión 2 del index"
    count = int.from_bytes(header[8:12], "big")

    entries = list()

    content = raw[12:]
    idx = 0
    for i in range(0, count):
        ctime_s = int.from_bytes(content[idx:idx+4], "big")
        ctime_ns = int.from_bytes(content[idx+4:idx+8], "big")
        mtime_s = int.from_bytes(content[idx+8:idx+12], "big")
        mtime_ns = int.from_bytes(content[idx+12:idx+16], "big")
        dev = int.from_bytes(content[idx+16:idx+20], "big")
        ino = int.from_bytes(content[idx+20:idx+24], "big")
        unused = int.from_bytes(content[idx+24:idx+26], "big")
        assert 0 == unused
        mode = int.from_bytes(content[idx+26:idx+28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111
        uid = int.from_bytes(content[idx+28:idx+32], "big")
        gid = int.from_bytes(content[idx+32:idx+36], "big")
        fsize = int.from_bytes(content[idx+36:idx+40], "big")
        sha = format(int.from_bytes(content[idx+40:idx+60], "big"), "040x")
        flags = int.from_bytes(content[idx+60:idx+62], "big")
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage = flags & 0b0011000000000000
        name_length = flags & 0b0000111111111111

        idx += 62

        if name_length < 0xFFF:
            assert content[idx + name_length] == 0x00
            raw_name = content[idx:idx+name_length]
            idx += name_length + 1
        else:
            print(f"El nombre es 0x{name_length:X} bytes largo")
            null_idx = content.find(b"\x00", idx + 0xFFF)
            raw_name = content[idx: null_idx]
            idx = null_idx + 1

        name = raw_name.decode("utf-8")

        idx = 8 * ceil(idx / 8)

        entries.append(GitIndexEntry(ctime=(ctime_s, ctime_ns),
                                     mtime=(mtime_s, mtime_ns),
                                     dev=dev,
                                     ino=ino,
                                     mode_type=mode_type,
                                     mode_perms=mode_perms,
                                     uid=uid,
                                     gid=gid,
                                     fsize=fsize,
                                     sha=sha,
                                     flag_assume_valid=flag_assume_valid,
                                     flag_stage=flag_stage,
                                     name=name))

    return GitIndex(version=version, entries=entries)
