from revengai.api import Endpoint
from revengai.misc.configuration import Configuration


class Base(object):
    def __init__(self):
        self.models = []
        self.config: Configuration = Configuration()
        self.endpoint: Endpoint = Endpoint(self.config)
