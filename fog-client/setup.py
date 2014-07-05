from distutils.core import setup
import py2exe

# if py2exe complains "can't find P", try one of the following workarounds:
#
# a. py2exe doesn't support zipped eggs - http://www.py2exe.org/index.cgi/ExeWithEggs
#  You should give the --always-unzip option to easy_install, or you can use setup.py directly
#  $ python setup.py install --record install.log --single-version-externally-managed
#  Don't forget to remove the previous zipped egg.
#
# b. Add an empty __init__.py to the P/ top-level directory, if it's missing
#  - this is due to a bug (or misleading documentation) in python's imp.find_module()

setup(
    console=["fog-client"],
    zipfile="py2exe-fog-client.zip",
    options={
        "py2exe": {
            "includes": ["pyptlib", "twisted", "txsocksx"],
            "packages": ["ometa", "terml", "zope.interface"],
        },
    },
)
