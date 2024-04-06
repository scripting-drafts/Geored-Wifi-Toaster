import pywifi
import pywifi.const as const
import time
import keyring
import logging
import time
import datetime
import creds
import subprocess
import random
import threading
import os
import queue as queue
from pythonping import ping

class Geored_Wifi_Server:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()

        self.logger = Logger().logging()

        self.cycle_len = .6
        self.threads_list = []
        self.urls = '8.8.8.8', '192.168.1.1', 'google.com'
                
    def heartbeats(self):
        return

    def keepalive(self, url):
            response = ping(url, verbose=False, timeout=1, size=1, count=1, interval=1.5)
            self.logger.info(str(response).split('\n')[0]) # , count=2, interval=3=

    def keepalived(self, mode):
        if mode == 'start':
            for url in self.urls:
                t = threading.Thread(target=self.keepalive, daemon=True, args=(url,))
                self.threads_list.append(t)
                t.start()

        elif mode == 'stop':
            for t in self.threads_list:
                t.join()

    def get_network_interfaces(self):
        '''
        ifaces is a list of objects with the attribute ifaces.name
        We assume ifaces will never be empty
        '''
        self.ifaces = self.wifi.interfaces()
        self.iface_a = self.ifaces[0]

        for u, w in enumerate(self.ifaces):
            self.logger.info(f'iface {u}:', w.name())

    def connect_ap(self, iface, ap):
        iface.remove_all_network_profiles()

        profile = pywifi.Profile()
        profile.ssid = ap
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        pwd = keyring.get_password('system', ap)
        profile.key = pwd
        
        iface.connect(profile)
        time.sleep(5)
        assert iface.status() == const.IFACE_CONNECTED

    def disable_software_radio(self, iface):
        iface.disconnect()
        time.sleep(.7)
        assert iface.status() in\
            [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]
        
    def enable_hardware_radio(self):
        subprocess.Popen('netsh interface set interface "WiFi" enable', shell=True).communicate()

    def disable_hardware_radio(self):
        '''TODO: Provide powershelll privileges'''
        subprocess.Popen('powershell.exe -noprofile "Start-Process -Verb RunAs -Wait powershell.exe -Args -noprofile; netsh interface set interface WiFi disable"',
                         shell=True, stdin=subprocess.PIPE).communicate()
        subprocess.Popen('netsh interface set interface "WiFi" disable', shell=True, stdin=subprocess.PIPE).communicate()

    def list_bss_attrs(self, bss):
        '''TODO:
        Retrieve handshake algorithm'''
        for i in bss:
            bssid = i.bssid
            ssid  = i.ssid
            signal = i.signal
            freq = i.freq
            auth = 'Authorized' if i.auth == [] else 'Unauthorized'
            # akm = i.akm
            alg = i.alg
            self.logger.info(f'{bssid}: {ssid}', signal, freq, auth, alg)

    def get_networks_list(self, iface):
        '''
        Service Set (bss) attributes are bssid, ssid, freq, auth, akm, signal

        TODO: Check if it gets connected automatically to each AP '''
        iface.scan()
        time.sleep(0.7)
        aps = iface.scan_results()

        self.list_bss_attrs(aps)

        return aps
    
    def get_available_aps(self):
        '''
        TODO: Retrieve hardware_radio status'''
        current_ap = subprocess.check_output(r'netsh WLAN show interfaces', encoding='utf-8')

        if current_ap:
            current_ap_status = current_ap.split('State')[1]
            self.current_ap_status = current_ap_status.split('SSID')[0].split(':')[1].split('\n')[0].strip()

            if self.current_ap_status == 'disconnected':
                self.software_radio = current_ap.split('Software')[1].split()[0].strip()
                self.current_ap_name = None

            elif self.current_ap_status == 'connected':
                self.software_radio = 'On'
                self.current_ap_name = current_ap.split('SSID')[1].split(':')[1].split('\n')[0].strip()
        
            self.logger.info(f'SW_Radio: {self.software_radio}')
            self.logger.info(f'AP_NAME: {self.current_ap_name}')
            self.logger.info(f'AP_STATUS: {self.current_ap_status}')

        else:
            self.software_radio = None
            self.current_ap_status = None
            self.current_ap_name = None

    def georedundancy(self):
        while True:
            try:
                self.keepalived(mode='start')
                self.get_available_aps()

                if self.software_radio == 'On':
                    if self.current_ap_status == 'disconnected':
                        
                        self.get_network_interfaces()
                        if len(self.iface_a.name()) == 0:
                            raise AssertionError('No network interfaces available')
                        
                        if self.current_ap_name is not None:

                            if self.current_ap_name == creds.ap_b:
                                target_ap = creds.ap_a
                            elif self.current_ap_name == creds.ap_a:
                                target_ap = creds.ap_b

                        elif self.current_ap_name is None:
                            target_ap = random.choice([creds.ap_a, creds.ap_b])

                        self.connect_ap(self.iface_a, target_ap)

                    elif self.current_ap_status is None:
                        '''TODO: Enable Network Interface from Device Manager'''
                        pass

                    elif self.current_ap_status == 'connected':
                        pass

                    else:
                        self.logger.error('Unknown AP or Interface error occurred')

                elif self.software_radio == 'Off' or self.software_radio is None:
                    '''TODO: Turn ON network interface'''
                    pass

                # time.sleep(self.cycle_len)
                self.keepalived(mode='stop')

            except Exception as e:
                self.logger.error(f'Unknown {e}')

class Logger:
    '''Reusable logger class'''
    def __init__(self):
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        os.system('')

    def RGB(self, red=None, green=None, blue=None, bg=False):
        '''Logger prettifier'''
        if(bg == False and red != None and green != None and blue != None):
            return f'\u001b[38;2;{red};{green};{blue}m'
        elif(bg == True and red != None and green != None and blue != None):
            return f'\u001b[48;2;{red};{green};{blue}m'
        elif(red == None and green == None and blue == None):
            return '\u001b[0m'

    def logging(self):
        # g0 = self.RGB()
        # g1 = self.RGB(127, 255, 212)
        # g2 = self.RGB(0, 0, 128)
        # bold = "\033[1m"
        # reset = "\033[0m"
        logging.basicConfig(filename='logs_toast.log', encoding='UTF-8', level=logging.DEBUG, format='%(asctime)s [%(name)s] %(message)s')
        logger = logging.getLogger('WIFI_TOASTER')
        logger.setLevel(logging.DEBUG)
        # ch = logging.StreamHandler()
        # ch.setLevel(logging.DEBUG)
        # formatter = logging.Formatter('%(asctime)s,%(msecs)03d {}{}[%(name)s]{}{} %(message)s'.format(bold, g1, g0, reset), '%H:%M:%S')
        # ch.setFormatter(formatter)
        # logger.addHandler(ch)

        return logger

wg = Geored_Wifi_Server()
wg.georedundancy()