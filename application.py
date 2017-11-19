from __future__ import print_function, division
import os
import signal

from jupyter_client import KernelManager
from jupyter_client.multikernelmanager import MultiKernelManager
from jupyter_client.threaded import ThreadedKernelClient
from jupyter_core.application import JupyterApp
from jupyter_client.consoleapp import JupyterConsoleApp, NoSuchKernel
from jupyter_client.ioloop import IOLoopKernelManager
from jupyter_core import version_info

from traceback import format_exc

from jupyter_container.kernelmanager import (
    ProxyMultiKernelManager,
    ThreadedIOLoopKernelManager,
)
from jupyter_container import __version__


class JupyterChildConsoleApp(JupyterConsoleApp):
    aliases = JupyterConsoleApp.aliases
    flags = JupyterConsoleApp.flags

    kernel_client_factory = ThreadedKernelClient

    def _connection_file_default(self):
        return 'kernel-%i-%i.json' % (os.getpid(), self.childid)

    def initialize(self, proxy_kernel_manager, argv=None):
        """
        Classes which mix this class in should call:
               JupyterConsoleApp.initialize(self,argv)
        """
        if self._dispatching:
            return
        self.init_connection_file()
        self.init_ssh()
        self.init_kernel_manager(proxy_kernel_manager)
        self.init_kernel_client()

    def init_kernel_manager(self, proxy_kernel_manager):
        # Don't let Qt or ZMQ swallow KeyboardInterupts.
        if self.existing:
            self.kernel_manager = None
            return

        # Create a KernelManager and start a kernel.
        try:
            kwargs = {
                'extra_constructor_kwargs': dict(
                    ip=self.ip,
                    session=self.session,
                    transport=self.transport,
                    shell_port=self.shell_port,
                    iopub_port=self.iopub_port,
                    stdin_port=self.stdin_port,
                    hb_port=self.hb_port,
                    connection_file=self.connection_file,
                    data_dir=self.data_dir),
            }
            kernel_id = proxy_kernel_manager.start_kernel(**kwargs)
            self.kernel_manager = proxy_kernel_manager.get_kernel(kernel_id)

        except NoSuchKernel:
            self.log.critical("Could not find kernel %s", self.kernel_name)
            self.exit(1)

        # self.kernel_manager.client_factory = self.kernel_client_class
        atexit.register(self.kernel_manager.cleanup_ipc_files)

        if self.sshserver:
            # ssh, write new connection file
            self.kernel_manager.write_connection_file()

        # in case KM defaults / ssh writing changes things:
        km = self.kernel_manager
        self.shell_port=km.shell_port
        self.iopub_port=km.iopub_port
        self.stdin_port=km.stdin_port
        self.hb_port=km.hb_port
        self.connection_file = km.connection_file

        atexit.register(self.kernel_manager.cleanup_connection_file)

class JupyterChildApp(JupyterApp, JupyterChildConsoleApp):
    kernel_manager_class = ThreadedIOLoopKernelManager
    aliases = JupyterChildConsoleApp.aliases
    flags = JupyterChildConsoleApp.flags

    def initialize(self, parent, childid, argv=None):
        """
        Classes which mix this class in should call:
               JupyterConsoleApp.initialize(self,argv)
        """
        self.parent = parent
        self.childid = childid
        super(JupyterChildApp, self).initialize(argv)
        JupyterChildConsoleApp.initialize(self, parent.kernel_manager, argv)


class JupyterContainerApp(JupyterApp):
    name = 'jupyter-container-app'
    version = __version__
    description = """
        The Jupyter Container App that can start JupyterChildApp
    """
    kernel_manager_factory = ProxyMultiKernelManager
    child_app_factory = JupyterChildApp

    classes = [
        JupyterChildApp,
        ProxyMultiKernelManager,
        ThreadedIOLoopKernelManager]

    def list_child_apps(self):
        """Return a list of the kernel ids of the active kernels."""
        # Create a copy so we can iterate over kernels in operations
        # that delete keys.
        return list(self._child_apps.keys())

    def __len__(self):
        """Return the number of running kernels."""
        return len(self._child_apps)

    def __contains__(self, bufno):
        return bufno in self._child_apps

    def init_kernel_manager(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        self.kernel_manager = self.kernel_manager_factory(
            parent=self,
            log=self.log,
        )

    def get_bufapp(self, childid):
        return self._child_apps.get(childid)


    def initialize(self, argv=None):
        self._child_apps = {}
        self._child_clients = {}
        super(JupyterContainerApp, self).initialize(argv)
        if self._dispatching:
            return
        self.init_kernel_manager()


    def start_child_app(self, childid, argv=None, **kwargs):
        if childid in self:
            assert argv is None or '--existing' not in argv, \
                'chilid is already associated with a kernel, --existing is not valid'
            logger.warning('BufApp %d already started', childid)
            return self._bufapps[childid]
        if 'log' not in kwargs:
            kwargs['log'] = self.log
        self.log.warning('=====')
        childapp = self.child_app_factory(**kwargs)
        childapp.initialize(self, childid, argv)

        self._child_apps[childid] = childapp
        self._child_clients[childid] = childapp.kernel_client
        return childapp
