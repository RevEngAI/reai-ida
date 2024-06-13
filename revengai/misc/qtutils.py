# -*- coding: utf-8 -*-

#################################################################
#                                                               #
# Copyright 2013, Christopher Billington, Philip Starkey        #
#                                                               #
# This file is part of the qtutils project                      #
# (see https://github.com/philipstarkey/qtutils )               #
# and is licensed under the 2-clause, or 3-clause, BSD License. #
#                                                               #
#################################################################


import functools
import itertools

from queue import Queue
from sys import exc_info
from threading import Thread

from idaapi import is_main_thread

from PyQt5.QtCore import QEvent, QObject, QCoreApplication


class CallEvent(QEvent):
    """An event containing a request for a function call."""
    EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

    def __init__(self, queue, exceptions_in_main, fn, *args, **kwargs):
        QEvent.__init__(self, self.EVENT_TYPE)

        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self._returnval = queue

        # Whether to raise exceptions in the main thread or store them
        # for raising in the calling thread:
        self._exceptions_in_main = exceptions_in_main


class Caller(QObject):
    """An event handler which calls the function held within a CallEvent."""

    def event(self, event: CallEvent) -> bool:
        event.accept()

        result = None
        exception = None

        try:
            result = event.fn(*event.args, **event.kwargs)
        except Exception:
            # Store for re-raising the exception in the calling thread:
            exception = exc_info()

            if event._exceptions_in_main:
                # Or, if nobody is listening for this exception,
                # better raise it here, so it doesn't pass silently:
                raise
        finally:
            event._returnval.put([result, exception])
        return True


caller = Caller()


def inmain(fn, *args, **kwargs) -> any:
    """Execute a function in the main thread. Wait for it to complete
    and return its return value.

    This function queues up a custom :code:`QEvent` to the Qt event loop.
    This event executes the specified function :code:`fn` in the Python
    MainThread with the specified arguments and keyword arguments, and returns the result to the calling thread.

    This function can be used from the MainThread, but such use will just directly call the function, bypassing the Qt event loop.

    Arguments:
        fn: A reference to the function or method to run in the MainThread.

        *args: Any arguments to pass to :code:`fn` when it is called from the
               MainThread.

        **kwargs: Any keyword arguments to pass to :code:`fn` when it is called
                  from the MainThread

    Returns:
        The result of executing :code:`fn(*args, **kwargs)`
    """
    if is_main_thread():
        return fn(*args, **kwargs)

    return get_inmain_result(_in_main_later(fn, False, *args, **kwargs))


def inmain_later(fn, *args, **kwargs) -> Queue:
    """Queue up the executing of a function in the main thread and return immediately.

    This function queues up a custom :code:`QEvent` to the Qt event loop.
    This event executes the specified function :code:`fn` in the Python
    MainThread with the specified arguments and keyword arguments, and returns
    a Python Queue which will eventually hold the result from the executing of
    :code:`fn`. To access the result, use :func:`qtutils.invoke_in_main.get_inmain_result`.

    This function can be used from the MainThread, but such use will just directly call the function, bypassing the Qt event loop.

    Arguments:
        fn: A reference to the function or method to run in the MainThread.

        *args: Any arguments to pass to :code:`fn` when it is called from the
               MainThread.

        **kwargs: Any keyword arguments to pass to :code:`fn` when it is called
                  from the MainThread

    Returns:
       A Python Queue which will eventually hold the result
       :code:`(fn(*args, **kwargs), exception)` where
       :code:`exception=[type,value,traceback]`.
    """
    return _in_main_later(fn, True, *args, **kwargs)


def _in_main_later(fn, exceptions_in_main: bool, *args, **kwargs) -> Queue:
    """Asks the mainloop to call a function when it has time. Immediately
    returns the queue that was sent to the mainloop.  A call to queue.get()
    will return a list of [result,exception] where exception=[type,value,traceback]
    of the exception.  Functions are guaranteed to be called in the order
    they were requested."""
    queue = Queue()
    QCoreApplication.postEvent(caller, CallEvent(queue, exceptions_in_main, fn, *args, **kwargs))
    return queue


def get_inmain_result(queue: Queue) -> any:
    """ Processes the result of :func:`qtutils.invoke_in_main.inmain_later`.

    This function takes the queue returned by :code:`inmain_later` and blocks
    until a result is obtained. If an exception occurred when executing the
    function in the MainThread, it is raised again here (it is also raised in the
    MainThread). If no exception was raised, the result from the execution of the
    function is returned.

    Arguments:
        queue: The Python Queue object returned by :code:`inmain_later`

    Returns:
        The result from executing the function specified in the call to
        :code:`inmain_later`
    """
    result, exception = queue.get()
    if exception is not None:
        _, value, traceback = exception
        raise value.with_traceback(traceback)
    return result


cont = itertools.count()


def inthread(f, *args, **kwargs) -> Thread:
    """A convenience function for starting a Python thread.

    This function launches a Python thread in Daemon mode, and returns a
    reference to the running thread object.

    Arguments:
        f: A reference to the target function to be executed in the Python thread.

        *args: Any arguments to pass to :code:`f` when it is executed in the
               new thread.

        **kwargs: Any keyword arguments to pass to :code:`f` when it is executed
                  in the new thread.

    Returns:
        A reference to the (already running) Python thread object
    """
    thread = Thread(target=f, args=args, kwargs=kwargs)
    thread.daemon = True
    thread.name = f"reai-{next(cont)}"
    thread.start()
    return thread


def inmain_decorator(wait_for_return=True, exceptions_in_main=True):
    """ A decorator which enforces the execution of the decorated thread to occur in the MainThread.

    This decorator wraps the decorated function or method in either
    :func:`qtutils.invoke_in_main.inmain` or
    :func:`qtutils.invoke_in_main.inmain_later`.

    Keyword Arguments:
        wait_for_return: Specifies whether to use :code:`inmain` (if
                         :code:`True`) or :code:`inmain_later` (if
                         :code:`False`).

        exceptions_in_main: Specifies whether the exceptions should be raised
                            in the main thread or not. This is ignored if
                            :code:`wait_for_return=True`. If this is
                            :code:`False`, then exceptions may be silenced if
                            you do not explicitly use
                            :func:`qtutils.invoke_in_main.get_inmain_result`.

    Returns:
        The decorator returns a function that has wrapped the decorated function
        in the appropriate call to :code:`inmain` or :code:`inmain_later` (if
        you are unfamiliar with how decorators work, please see the Python
        documentation).

        When calling the decorated function, the result is either the result of
        the function executed in the MainThread (if :code:`wait_for_return=True`)
        or a Python Queue to be used with
        :func:`qtutils.invoke_in_main.get_inmain_result` at a later time.
    """

    def wrap(fn):
        """A decorator which sets any function to always run in the main thread."""

        @functools.wraps(fn)
        def f(*args, **kwargs):
            if wait_for_return:
                return inmain(fn, *args, **kwargs)
            return _in_main_later(fn, exceptions_in_main, *args, **kwargs)

        return f

    return wrap
