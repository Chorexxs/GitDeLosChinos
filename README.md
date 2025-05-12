````markdown
# GitDeLosChinos

**GitDeLosChinos** es una implementación básica del sistema de control de versiones Git, desarrollada completamente en Python. Este proyecto busca replicar las funcionalidades fundamentales de Git desde cero, permitiendo comprender y manipular su estructura interna (índice, árboles, commits) sin depender del binario de Git.

---

## 🚀 Características implementadas

- ✅ `add` – Añade archivos al índice (staging area)
- ✅ `rm` – Elimina archivos del índice y del directorio de trabajo
- ✅ `status` – Muestra diferencias entre el índice y el working directory
- ✅ `commit` – Registra cambios en el repositorio
- ✅ Escritura manual del archivo `.git/index`
- ✅ Generación del árbol de directorios (`tree`) para los commits
- ✅ Creación de objetos `commit` con metadatos del autor y zona horaria
- ✅ Soporte parcial para `.gitignore`

---

## 📁 Estructura del proyecto

```bash
.
├── GitDeLosChinos/
│   ├── libwyag.py
│   ├── README.md
│   ├── wyag
```
````

---

## 🧪 Requisitos

- Python 3.8+
- Sin dependencias externas (uso exclusivo de la librería estándar)

---

---

## 👤 Configuración del usuario

GitDeLosChinos lee la configuración del usuario desde `~/.gitconfig` o `~/.config/git/config`. Asegúrate de tener algo como:

```ini
[user]
    name = Tu Nombre
    email = tu@email.com
```

---

## 📚 Objetivos de aprendizaje

Este proyecto está diseñado para ayudarme a entender:

- Cómo funciona Git a nivel interno
- Cómo se serializan y almacenan objetos (`blob`, `tree`, `commit`)
- El funcionamiento del índice (`index`)
- Cómo se organiza un repositorio `.git` a bajo nivel

---

## 🧠 Inspiración

Este proyecto se inspira en:

- [Write yourself a Git](https://wyag.thb.lt/)

---

## 📜 Licencia

MIT License © 2025 — [@Chorexxs]

---

## 🧑‍💻 Autor

- 💼 [LinkedIn](https://www.linkedin.com/in/oswaldo-fonseca-gonzalez/)
- 🧑‍💻 [GitHub](https://github.com/Chorexxs)
- 🌐 [Portafolio](https://chorexxs-portfolio.dev/)
