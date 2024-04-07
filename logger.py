import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
os.system('')

class Logger:
    '''Reusable logger class'''

    def logging(self):
        logging.basicConfig(filename='logs_toast.log', encoding='UTF-8', level=logging.DEBUG, format='%(asctime)s [%(name)s] %(message)s')
        logger = logging.getLogger('WIFI_TOASTER')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler('logs_toast.log')
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

        return logger