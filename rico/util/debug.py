import os, sys, re
import inspect

class Debug():

    @staticmethod
    def debug_log():
        stack = inspect.stack()
        caller = stack[2]
        callee = stack[1]

        print( '{} [{}]: ({}) {} \'{}\''.format(caller.frame.f_globals['__name__'],
                                         caller.lineno,
                                         callee.function,
                                         callee.frame.f_globals['__name__'],
                                         caller.code_context[0].rstrip()))

