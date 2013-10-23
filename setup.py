from distutils.core import setup
import py2exe

setup(
    console=["obfs-flash-client"],
    zipfile="py2exe-obfs-flash-client.zip",
    options={
        "py2exe": {
            "includes": ["pyptlib", "twisted"],
            "packages": ["ometa", "terml"],
        },
    },
)
