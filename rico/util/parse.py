from functools import reduce
from rico.util.debug import Debug

class Parse():

    """
    @staticmethod
    def print_dict(data, count=0):
        if type(data) is dict:
            for key, value in data.items():
                if type(value) is dict:
                    print('{:^{spacing}}{:15} :'.format('', key, spacing=str(count*4)))
                    print_dict(value, (count+1))

                elif type(value) is list :
                    print_dict(value, (count+1))
                else:
                    print('{:^{spacing}}{:15} : {}'.format('', key, value, spacing=str(count*4)))

        elif type(data) is list:
            for item in data:
                if type(item) is dict or type(item) is list:
                    print_dict(item, (count+1))
                else:
                    print('{:^{spacing}}{:15}'.format('', item, spacing=str(count*4)))
    """

    @staticmethod
    def get_dict_safe(dictionary, keys, default=None):
        return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)

    @staticmethod
    def print_dict(data, count=0):
        if type(data) is dict:
            for key, value in data.items():
                if type(value) is dict:
                    print('{:^{spacing}}{:15}'.format('', key, spacing=str(count*4)))
                    Parse.print_dict(value, (count+1))
                elif type(value) is list :
                    Parse.print_dict(value, (count+1))
                else:
                    print('{:^{spacing}}{:15} : {}'.format('', key, value, spacing=str(count*4)))

        elif type(data) is list:
            for item in data:
                if type(item) is dict or type(item) is list:
                    Parse.print_dict(item, (count+1))
                else:
                    print('{:^{spacing}}{:15}'.format('', item, spacing=str(count*4)))
