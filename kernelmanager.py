
"""A MultiKernelManager for use in the notebook webserver

- raises HTTPErrors
- creates REST API models
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os

from tornado import gen, web
from tornado.concurrent import Future
from tornado.ioloop import IOLoop

from jupyter_client.consoleapp import JupyterConsoleApp
from jupyter_client.multikernelmanager import (
    MultiKernelManager,
    DuplicateKernelError,
    unicode_type,
    uuid,
)
from jupyter_client.ioloop import IOLoopKernelManager
from jupyter_client.threaded import ThreadedKernelClient
from traitlets import Dict, List, Unicode, TraitError, default, validate

from ipython_genutils.py3compat import getcwd
# import jupyter_nvim


class ThreadedIOLoopKernelManager(IOLoopKernelManager):
    client_factory = ThreadedKernelClient

    # TODO: overwrite this one, initially in KernelManager.start_kernel




class ProxyMultiKernelManager(MultiKernelManager):
    # @default('kernel_manager_class')
    # def _default_kernel_manager_class(self):
    #     return "jupyter_nvim.kernelmanager.ThreadedIOLoopKernelManager"
    # this is simpler
    kernel_manager_factory = ThreadedIOLoopKernelManager

    def start_kernel(self, kernel_name=None, **kwargs):
        """Start a new kernel.

        The caller can pick a kernel_id by passing one in as a keyword arg,
        otherwise one will be picked using a uuid.

        The kernel ID for the newly started kernel is returned.
        """
        kernel_id = kwargs.pop('kernel_id', unicode_type(uuid.uuid4()))
        if kernel_id in self:
            raise DuplicateKernelError('Kernel already exists: %s' % kernel_id)

        if kernel_name is None:
            kernel_name = self.default_kernel_name
        # kernel_manager_factory is the constructor for the KernelManager
        # subclass we are using. It can be configured as any Configurable,
        # including things like its transport and ip.
        constructor_kwargs = dict(
            connection_file=os.path.join(
                self.connection_dir, "kernel-%s.json" % kernel_id),
            parent=self, log=self.log, kernel_name=kernel_name
        )
        if self.kernel_spec_manager:
            constructor_kwargs['kernel_spec_manager'] = self.kernel_spec_manager
        extra_constructor_kwargs = kwargs.pop('extra_constructor_kwargs', {})
        constructor_kwargs.update(extra_constructor_kwargs)

        kernel_manager_factory = self.kernel_manager_factory
        km = kernel_manager_factory(**constructor_kwargs)
        km.start_kernel(**kwargs)
        self._kernels[kernel_id] = km
        return kernel_id

    # def register_kernel(self, child_kernel_manager, **kwargs):
    #     kernel_id = kwargs.pop('kernel_id', unicode_type(uuid.uuid4()))
    #     if kernel_id in self:
    #         raise DuplicateKernelError('Kernel already exists: %s' % kernel_id)
    #     self._kernels[kernel_id] = child_kernel_manager
    #     child_kernel_manager.start_kernel(**kwargs)
    #     return kernel_id

    # def start_kernel(self, **kwargs):
    #     raise ValueError('ProxyMultiKernelManager cannot start new kernel, use register_kernel to add existing kernels')
