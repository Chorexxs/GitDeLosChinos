# Importación de módulos necesarios para el funcionamiento del script
import argparse  # Para manejar argumentos de línea de comandos
import configparser  # Para manejar archivos de configuración
from datetime import datetime  # Para manejar fechas y horas
import grp  # Para obtener información de grupos del sistema
import pwd  # Para obtener información de usuarios del sistema
from fnmatch import fnmatch  # Para realizar coincidencias de patrones
import hashlib  # Para calcular hashes (SHA-1)
from math import ceil  # Para redondeo hacia arriba
import os  # Para operaciones del sistema de archivos
import re  # Para trabajar con expresiones regulares
import zlib  # Para compresión y descompresión de datos
import sys  # Para manejar argumentos de línea de comandos y salida estándar

# Configuración del analizador de argumentos de línea de comandos
argparse = argparse.ArgumentParser(
    description="Un seguidor de contenido de los Chinos")  # Descripción del programa
argsubparsers = argparse.add_subparsers(
    title="Comandos", dest="comando")  # Subcomandos disponibles

# Función principal que maneja los comandos proporcionados por el usuario


def main(argv=sys.argv[1:]):
    """
    Función principal que analiza los argumentos de línea de comandos y ejecuta
    el comando correspondiente.
    """
    args = argparse.parse_args(argv)  # Analiza los argumentos
    match args.comando:  # Ejecuta el comando correspondiente
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
        # Mensaje de error si el comando no es válido
        case _: print("Comando no válido")

# Clase que representa un repositorio de Git


class GitRepository(object):
    """
    Representa un repositorio de Git. Contiene información sobre el directorio
    de trabajo, el directorio .git y la configuración del repositorio.
    """
    worktree = None  # Directorio de trabajo del repositorio
    gitdir = None  # Directorio .git del repositorio
    conf = None  # Configuración del repositorio

    def __init__(self, path, force=False):
        """
        Inicializa un repositorio de Git.

        :param path: Ruta al directorio del repositorio
        :param force: Si es True, fuerza la creación del repositorio
        """
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")

        # Verifica si el directorio .git existe, a menos que se fuerce
        if not (force or os.path.isdir(self.gitdir)):
            raise Exception(f"No es un repositorio de Git válido: {path}")

        # Lee el archivo de configuración en .git/config
        self.conf = configparser.ConfigParser()
        cf = repo_file(self, "config")

        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Archivo de configuración no encontrado")

        # Verifica la versión del formato del repositorio
        if not force:
            vers = int(self.conf.get("core", "repositoryformatversion"))
            if vers != 0:
                raise Exception(
                    f"Versión de formato de repositorio no soportada: {vers}")

# Función para calcular la ruta absoluta de un archivo en el repositorio


def repo_path(repo, *path):
    """
    Calcula la ruta absoluta de un archivo en el repositorio.

    :param repo: Instancia de GitRepository
    :param path: Componentes de la ruta relativa
    :return: Ruta absoluta
    """
    return os.path.join(repo.gitdir, *path)

# Función para calcular la ruta de un archivo y crear directorios si es necesario


def repo_file(repo, *path, mkdir=False):
    """
    Calcula la ruta de un archivo en el repositorio y crea los directorios
    necesarios si no existen.

    :param repo: Instancia de GitRepository
    :param path: Componentes de la ruta relativa
    :param mkdir: Si es True, crea los directorios necesarios
    :return: Ruta absoluta del archivo
    """
    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)

# Función para calcular la ruta de un directorio y crearla si es necesario


def repo_dir(repo, *path, mkdir=False):
    """
    Calcula la ruta de un directorio en el repositorio y crea el directorio
    si no existe.

    :param repo: Instancia de GitRepository
    :param path: Componentes de la ruta relativa
    :param mkdir: Si es True, crea el directorio si no existe
    :return: Ruta absoluta del directorio
    """
    path = repo_path(repo, *path)

    if os.path.exists(path):
        if os.path.isdir(path):
            return path
        else:
            raise Exception(f"No es un directorio {path}")

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None

# Función para crear un nuevo repositorio


def repo_create(path):
    """
    Crea un nuevo repositorio en la ruta especificada.

    :param path: Ruta donde se creará el repositorio
    :return: Instancia de GitRepository
    """
    repo = GitRepository(path, True)

    # Verifica que el directorio sea válido
    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception(f"{path} no es un directorio")
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception(f"{path} no es un directorio vacío")
    else:
        os.makedirs(repo.worktree)

    # Crea los directorios y archivos necesarios
    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)

    # Archivo de descripción
    with open(repo_file(repo, "descripción"), "w") as f:
        f.write(
            "repositorio sin nombre; edita el archivo 'descripción' para cambiarlo\n")

    # Archivo HEAD
    with open(repo_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")

    # Archivo de configuración
    with open(repo_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)

    return repo

# Función para obtener la configuración por defecto del repositorio


def repo_default_config():
    """
    Devuelve la configuración por defecto del repositorio.

    :return: Configuración por defecto como instancia de ConfigParser
    """
    ret = configparser.ConfigParser()

    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret


# Comando init para inicializar un nuevo repositorio
argsp = argsubparsers.add_parser(
    "init", help="Inicia un nuevo repositorio vacío")

argsp.add_argument("path",
                   metavar="directorio",
                   nargs="?",
                   default=".",
                   help="Donde crear el repositorio.")


def cmd_init(args):
    """
    Comando para inicializar un nuevo repositorio vacío.

    :param args: Argumentos de línea de comandos
    """
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
    """
    Encuentra un objeto en el repositorio a partir de su nombre o referencia.

    :param repo: Instancia de GitRepository
    :param name: Nombre o referencia del objeto
    :param fmt: Tipo de objeto esperado (opcional)
    :param follow: Si es True, sigue referencias como tags o commits (opcional)
    :return: SHA-1 del objeto encontrado
    """
    sha = object_resolve(repo, name)

    if not sha:
        raise Exception(f"Referencia no válida: {name}")

    if len(sha) > 1:
        raise Exception(
            f"Referencia ambigua {name}: Los candidatos son:\n - {'\n - '.join(sha)}.")

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
            # Si es un tag, sigue la referencia al objeto apuntado
            sha = obj.kvlm[b"object"].decode("ascii")
        elif obj.fmt == b"commit" and fmt == b"tree":
            # Si es un commit, sigue la referencia al árbol
            sha = obj.kvlm[b"tree"].decode("ascii")
        else:
            return None


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


def object_hash(fd, fmt, repo=None):
    """Objeto hash, escrito en el repo si se provee"""
    data = fd.read()

    # Elige el constructor de acuerdo al argumento fmt
    match fmt:
        case b"commit": obj = GitCommit(data)
        case b"tree": obj = GitTree(data)
        case b"tag": obj = GitTag(data)
        case b"blob": obj = GitBlob(data)
        case _: raise Exception(f"Tipo desconocido {fmt}!")

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

    # Si el objeto es un commit, obtiene el tree
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

# EL COMANDO ls-files


argsp = argsubparsers.add_parser("ls-files",
                                 help="Lista todos los archivos")

argsp.add_argument("--verbose",
                   action="store_true",
                   help="Lo muestra todo")


def cmd_ls_files(args):
    repo = repo_find()
    index = index_read(repo)
    if args.verbose:
        print(
            f"Formato del archivo en el Index v{index.version}, contiene {len(index.entries)} entradas")

    for e in index.entries:
        print(e.name)
        if args.verbose:
            entry_type = {0b1000: "regular",
                          0b1010: "symlink",
                          0b1110: "git link"}[e.mode_type]
            print(f"{entry_type} con permisos: {e.mode_perms:o}")
            print(f"En blob: {e.sha}")
            print(
                f"Creado {datetime.fromtimestamp(e.ctime[0])}.{e.ctime[1]}, modificado: {datetime.fromtimestamp(e.mtime[0])}.{e.mtime[1]}")
            print(f"Dispositivo: {e.dev}, inodo: {e.ino}")
            print(
                f"Usuario: {pwd.getpwuid(e.uid).pw_name} ({e.uid} grupo: {grp.getgrgid(e.gid).gr_name} ({e.gid}))")
            print(
                f"flags: stage={e.flag_stage} assume_valid={e.flag_assume_valid}")

# EL COMANDO check-ignore


argsp = argsubparsers.add_parser("check-ignore",
                                 help="Verifica rutas contra las reglas de ignorados")

argsp.add_argument("path",
                   nargs="+",
                   help="Rutas a verificar")


def cmd_check_ignore(args):
    repo = repo_find()
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(rules, path):
            print(path)


def gitignore_parse1(raw):
    raw = raw.strip()

    if not raw or raw[0] == "#":
        return None
    elif raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "\\":
        return (raw[1:], True)
    else:
        return (raw, True)


def gitignore_parse(lines):
    ret = list()

    for line in lines:
        parsed = gitignore_parse1(line)
        if parsed:
            ret.append(parsed)
    return ret


class GitIgnore(object):
    absolute = None
    scoped = None

    def __init__(self, absolute, scoped):
        self.absolute = absolute
        self.scoped = scoped


def gitignore_read(repo):
    ret = GitIgnore(absolute=list(), scoped=list())

    repo_file = os.path.join(repo.gitdir, "info/exclude")
    if os.path.exists(repo_file):
        with open(repo_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")
    global_file = os.path.join(config_home, "git/ignore")

    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    index = index_read(repo)

    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            lines = contents.blobdata.decode("utf-8").splitlines()
            ret.scoped[dir_name] = gitignore_parse(lines)
    return ret


def check_ignore1(rules, path):
    result = None
    for (pattern, value) in rules:
        if fnmatch(path, pattern):
            result = value
    return result


def check_ignore_scoped(rules, path):
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore1(rules[parent], path)
            if result != None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None


def check_ignore_absolute(rules, path):
    parent = os.path.dirname(path)
    for ruleset in rules:
        result = check_ignore1(ruleset, path)
        if result != None:
            return result
    return False


def check_ignore(rules, path):
    if os.path.isabs(path):
        raise Exception(
            "Esta función requiere que el path sea relativo a la raíz del repositorio")

    result = check_ignore_scoped(rules.scoped, path)
    if result != None:
        return result

    return check_ignore_absolute(rules.absolute, path)

# EL COMANDO status


argsp = argsubparsers.add_parser("status",
                                 help="Muestra el estado del repositorio")


def cmd_status(_):
    repo = repo_find()
    index = index_read(repo)

    cmd_status_branch(repo)
    cmd_status_head_index(repo, index)
    print()
    cmd_status_index_worktree(repo, index)

# branch activa


def branch_get_active(repo):
    with open(repo_file(repo, "HEAD"), "r") as f:
        head = f.read()

    if head.startswith("ref: refs/heads/"):
        return (head[16:-1])
    else:
        return False


def branch_status_branch(repo):
    branch = branch_get_active(repo)
    if branch:
        print(f"En la rama {branch}.")
    else:
        print(f"HEAD está separado en {object_find(repo, 'HEAD')}")

# Cambios entre HEAD y el index


def tree_to_dict(repo, ref, prefix=""):
    ret = dict()
    tree_sha = object_find(repo, ref, fmt=b"tree")
    tree = object_read(repo, tree_sha)

    for leaf in tree.items:
        full_path = os.path.join(prefix, leaf.path)

        is_subtree = leaf.mode.startswith(b"04")

        if is_subtree:
            ret.update(tree_to_dict(repo, leaf.sha, full_path))
        else:
            ret[full_path] = leaf.sha
    return ret


def cmd_status_head_index(repo, index):
    print("Cambios para ser confirmados")

    head = tree_to_dict(repo, "HEAD")
    for entry in index.entries:
        if entry.name in head:
            if head[entry.name] != entry.sha:
                print(" modificado:", entry.name)
            del head[entry.name]
        else:
            print(" Añadiddo: ", entry.name)

    for entry in head.keys():
        print(" Eliminado: ", entry)

# Cambios entre index y worktree


def cmd_status_index_worktree(repo, index):
    print("Cambios no preparados para el commit")

    ignore = gitignore_read(repo)

    gitdir_prefix = repo.gitdir + os.path.sep

    all_files = list()

    for (root, _, files) in os.walk(repo.worktree, True):
        if root == repo.gitdir or root.startswith(gitdir_prefix):
            continue
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, repo.worktree)
            all_files.append(rel_path)

    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)

        if not os.path.exists(full_path):
            print(" Eliminado: ", entry.name)
        else:
            stat = os.stat(full_path)

            ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
            mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
            if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                with open(full_path, "rb") as fd:
                    new_sha = object_hash(fd, b"blob", None)
                    same = entry.sha == new_sha

                    if not same:
                        print(" Modificado: ", entry.name)

        if entry.name in all_files:
            all_files.remove(entry.name)

    print()
    print("Archivos no rastreados")

    for f in all_files:
        if not check_ignore(ignore, f):
            print(" ", f)

# Preparar y confirmar cambios (staging and committing)

# Creando el index_write()


def index_write(repo, index):
    """
    Escribe el índice del repositorio en el archivo correspondiente.

    :param repo: Instancia de GitRepository
    :param index: Instancia de GitIndex que contiene las entradas del índice
    """
    with open(repo_file(repo, "index"), "wb") as f:
        # Escribe la cabecera del índice
        f.write(b"DIRC")  # Firma del índice
        f.write(index.version.to_bytes(4, "big"))  # Versión del índice
        f.write(len(index.entries).to_bytes(4, "big"))  # Número de entradas

        # Escribe cada entrada del índice
        for e in index.entries:
            f.write(e.ctime[0].to_bytes(4, "big"))  # ctime (segundos)
            f.write(e.ctime[1].to_bytes(4, "big"))  # ctime (nanosegundos)
            f.write(e.mtime[0].to_bytes(4, "big"))  # mtime (segundos)
            f.write(e.mtime[1].to_bytes(4, "big"))  # mtime (nanosegundos)
            f.write(e.dev.to_bytes(4, "big"))  # ID del dispositivo
            f.write(e.ino.to_bytes(4, "big"))  # Número de inodo

            # Calcula y escribe el modo del archivo
            mode = (e.mode_type << 12) | e.mode_perms
            f.write(mode.to_bytes(4, "big"))

            f.write(e.uid.to_bytes(4, "big"))  # ID del usuario
            f.write(e.gid.to_bytes(4, "big"))  # ID del grupo
            f.write(e.fsize.to_bytes(4, "big"))  # Tamaño del archivo
            f.write(int(e.sha, 16).to_bytes(20, "big"))  # SHA-1 del objeto

            # Calcula y escribe los flags
            flag_assume_valid = 0x1 << 15 if e.flag_assume_valid else 0
            name_bytes = e.name.encode("utf-8")
            name_length = len(name_bytes) if len(name_bytes) < 0xFFF else 0xFFF
            f.write((flag_assume_valid | e.flag_stage |
                    name_length).to_bytes(2, "big"))
            f.write(name_bytes)  # Nombre del archivo
            f.write(b"\x00")  # Byte nulo para terminar el nombre

            # Alinea la entrada a un múltiplo de 8 bytes
            padding = (8 - (f.tell() % 8)) % 8
            f.write(b"\x00" * padding)

# EL COMANDO rm


argsp = argsubparsers.add_parser("rm",
                                 help="Elimina archivos del index y del directorio de trabajo")
argsp.add_argument("path",
                   nargs="+",
                   help="Archivos a eliminar")


def cmd_rm(args):
    repo = repo_find()
    rm(repo, args.path)


def rm(repo, paths, delete=True, skip_missing=False):
    index = index_read(repo)

    worktree = repo.worktree + os.sep

    abspaths = set()
    for path in paths:
        abspath = os.path.abspath(path)
        if abspath.startswith(worktree):
            abspaths.add(abspath)
        else:
            raise Exception(
                f"No se puede eliminar {paths} fuera del directorio de trabajo")

    kept_entries = list()
    remove = list()

    for e in index.entries:
        full_path = os.path.join(repo.worktree, e.name)

        if full_path in abspaths:
            remove.append(full_path)
            abspaths.remove(full_path)
        else:
            kept_entries.append(e)

    if len(abspaths) > 0 and not skip_missing:
        raise Exception(
            f"No se pueden eliminar paths que no están en el index: {abspaths}")

    if delete:
        for path in remove:
            os.unlink(path)

    index.entries = kept_entries
    index_write(repo, index)

# EL COMANDO add


argsp = argsubparsers.add_parser("add",
                                 help="Agrega archivos al index")
argsp.add_argument("path",
                   nargs="+",
                   help="Archivos a agregar al index")


def cmd_add(args):
    repo = repo_find()
    add(repo, args.path)


def add(repo, paths, delete=True, skip_missing=False):
    rm(repo, paths, delete=False, skip_missing=True)

    worktree = repo.worktree + os.sep

    clean_paths = set()
    for path in paths:
        abspath = os.path.abspath(path)
        if not (abspath.startswith(worktree) and os.path.isfile(abspath)):
            raise Exception(
                f"No se puede agregar {paths} fuera del directorio de trabajo")
        relpath = os.path.relpath(abspath, repo.worktree)
        clean_paths.add((abspath, relpath))

    index = index_read(repo)
    for (abspath, relpath) in clean_paths:
        with open(abspath, "rb") as fd:
            sha = object_hash(fd, b"blob", repo)

            stat = os.stat(abspath)

            ctime_s = int(stat.st_ctime)
            ctime_ns = stat.st_ctime_ns % 10**9
            mtime_s = int(stat.st_mtime)
            mtime_ns = stat.st_mtime_ns % 10**9

            entry = GitIndexEntry(ctime=(ctime_s, ctime_ns), mtime=(mtime_s, mtime_ns),
                                  dev=stat.st_dev, ino=stat.st_ino,
                                  mode_type=0b1000, mode_perms=0o644,
                                  uid=stat.st_uid, gid=stat.st_gid,
                                  fsize=stat.st_size, sha=sha,
                                  flag_assume_valid=False, flag_stage=False,
                                  name=relpath)

            index.entries.append(entry)

    index_write(repo, index)

# EL COMANDO commit


argsp = argsubparsers.add_parser("commit",
                                 help="Registrar cambios en el repositorio")


def gitconfig_read():
    xdg_config_home = os.environ["XDG_CONFIG_HOME"] if "XDG_CONFIG_HOME" in os.environ else "~/.config"
    configfiles = [
        os.path.expanduser(os.path.join(xdg_config_home, "git/config")),
        os.path.expanduser("~/.gitconfig")
    ]

    config = configparser.ConfigParser()
    config.read(configfiles)
    return config


def gitconfig_user_get(config):
    if "user" in config:
        if "name" in config["user"] and "email" in config["user"]:
            return f"{config['user']} <{config['user']['email']}>"
    return None


def tree_from_index(repo, index):
    contents = dict()
    contents[""] = list()

    for entry in index.entries:
        dirname = os.path.dirname(entry.name)

        key = dirname
        while key != "":
            if not key in contents:
                contents[key] = list()
            key = os. path.dirname(key)

        contents[dirname].append(entry)

    sorted_paths = sorted(contents.keys(), key=len, reverse=True)

    sha = None

    for path in sorted_paths:
        tree = GitTree()

        for entry in contents[path]:
            if isinstance(entry, GitIndexEntry):
                leaf_mode = f"{entry.mode_type:02o}{entry.mode_perms:04o}".encode(
                    "ascii")
                leaf = GitTreeLeaf(mode=leaf_mode, path=os.path.basename(
                    entry.name), sha=entry.sha)
            else:
                leaf = GitTreeLeaf(mode=b"040000", path=entry[0], sha=entry[1])

            tree.items.append(leaf)

        sha = object_write(tree, repo)

        parent = os.path.dirname(path)
        base = os.path.basename(path)
        contents[parent].append((base, sha))

    return sha


def commit_create(repo, tree, parent, author, timestamp, message):
    commit = GitCommit()
    commit.kvlm[b"tree"] = tree.encode("ascii")
    if parent:
        commit.kvlm[b"parent"] = parent.encode("ascii")

    mesage = message.strip() + "\n"

    offset = int(timestamp.astimezone().utcoffset().total_seconds())
    hours = offset // 3600
    minutes = (offset % 3600) // 60
    tz = "{}{:02}{:02}".format("+" if offset > 0 else "-", hours, minutes)

    author = author + timestamp.strftime(" %s ") + tz

    commit.kvlm[b"author"] = author.encode("utf-8")
    commit.kvlm[b"committer"] = author.encode("utf-8")
    commit.kvlm[None] = message.encode("utf-8")

    return object_write(commit, repo)


def cmd_commit(args):
    repo = repo_find()
    index = index_read(repo)

    tree = tree_from_index(repo, index)

    commit = commit_create(repo,
                           tree,
                           object_find(repo, "HEAD"),
                           gitconfig_user_get(gitconfig_read()),
                           datetime.now(),
                           args.message)

    active_branch = branch_get_active(repo)
    if active_branch:
        with open(repo_file(repo, os.path.join("refs/heads", active_branch)), "w") as fd:
            fd.write(commit + "\n")
    else:
        with open(repo_file(repo, "HEAD"), "w") as fd:
            fd.write("\n")
