import logging
import os


class Logger():

    logging.basicConfig(format=os.getenv("LOG_FORMAT"),
                        datefmt=os.getenv("LOG_DATE_FORMAT"))

    def __init__(self, name):
        self.__logger = logging.getLogger(name)
        self.__logger.setLevel(logging.DEBUG)

    def getLogger(self):
        return self.__logger
