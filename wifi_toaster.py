import pywifi
import pywifi.const as const
import time
import keyring
import time
import creds
import subprocess
import random
import threading
from logger import Logger
import queue as queue
from pythonping import ping

class Geored_Wifi_Server:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()

        self.logging = Logger().logging()

        self.threads_list = []
        self.urls = '8.8.8.8', '192.168.1.1', 'google.com'
        self.ping_results = []

    def disable_software_radio(self, iface):
        iface.disconnect()
        time.sleep(.7)
        assert iface.status() in\
            [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]
        
    def enable_hardware_radio(self):
        '''Enables hardware WiFi radio'''
        subprocess.Popen('netsh interface set interface "WiFi" enable', shell=True).communicate()

    def disable_hardware_radio(self):
        '''Disables hardware WiFi radio'''
        '''TODO: Provide powershelll privileges'''
        subprocess.Popen('powershell.exe -noprofile "Start-Process -Verb RunAs -Wait powershell.exe -Args -noprofile; netsh interface set interface WiFi disable"',
                         shell=True, stdin=subprocess.PIPE).communicate()
        subprocess.Popen('netsh interface set interface "WiFi" disable', shell=True, stdin=subprocess.PIPE).communicate()

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
        time.sleep(30)
        assert iface.status() == const.IFACE_CONNECTED

    def get_network_interfaces(self):
        '''
        ifaces is a list of objects with the attribute ifaces.name
        We assume ifaces will never be empty
        '''
        self.ifaces = self.wifi.interfaces()
        self.iface_a = self.ifaces[0]
        # self.logging.info(self.iface_a.name)

        for u, w in enumerate(self.ifaces):
            self.logging.info(f'iface {u}: {w.name()}' )

    def list_ap_attrs(self):
        '''List all bss attributes'''
        '''TODO:
        Retrieve handshake algorithm name'''

        for i in list(self.aps):
            bssid = i.bssid
            ssid  = i.ssid
            signal = i.signal
            freq = i.freq
            auth = i.auth
            akm = i.akm
            # alg = i.alg
            profit = bssid, ssid, signal, freq, auth, akm
            self.logging.info(profit)

    def get_networks_list(self, iface):
        '''Fetch Available APs list
        Service Set (bss) attributes are bssid, ssid, freq, auth, akm, signal
        TODO: Check if it gets connected automatically to each AP '''
        iface.scan()
        time.sleep(0.7)
        aps = iface.scan_results()
        self.aps = aps

    def get_network_status(self):
        '''
        TODO: Retrieve hardware_radio status'''
        current_ap = subprocess.check_output(r'netsh WLAN show interfaces', encoding='utf-8')

        if current_ap:
            ap_current_status = current_ap.split('State')[1]
            self.ap_current_status = ap_current_status.split('SSID')[0].split(':')[1].split('\n')[0].strip()
            self.ap_disconnected_status = 'disconnected', 'disconnecting'

            if self.ap_current_status in self.ap_disconnected_status:
                self.hardware_radio = current_ap.split('Hardware')[1].split()[0].strip()
                self.software_radio = current_ap.split('Software')[1].split()[0].strip()
                self.current_ap_name = None

            elif self.ap_current_status == 'connected':
                self.hardware_radio = 'On'
                self.software_radio = 'On'
                self.current_ap_name = current_ap.split('SSID')[1].split(':')[1].split('\n')[0].strip()

            elif self.ap_current_status == 'discovering':
                disco_wait = 5
                self.logging.info('AP_STATUS: DISCOVERING, wait %d seconds', disco_wait)
                time.sleep(disco_wait)
        
            self.logging.info(f'HW_Radio: {self.hardware_radio}')
            self.logging.info(f'SW_Radio: {self.software_radio}')
            self.logging.info(f'AP_NAME: {self.current_ap_name}')
            self.logging.info(f'AP_STATUS: {self.ap_current_status}')

        else:
            self.software_radio = None
            self.ap_current_status = None
            self.current_ap_name = None

    def keepalived(self, mode):
        if mode == 'start':
            for url in self.urls:
                t = threading.Thread(target=self.keepalive_service, daemon=True, args=(url,))
                self.threads_list.append(t)
                t.start()

        elif mode == 'stop':
            for t in self.threads_list:
                t.join()
                self.ping_results = []

    def keepalive_service(self, url):
        try:
            response = ping(url, verbose=False, timeout=1, size=1, count=1, interval=.8)
            response_str = str(response).split('\n')[0].strip()
            self.logging.info(response_str)

            if response.success():
                self.ping_results.append(True)

            else:
                self.ping_results.append(True)

        except Exception:
            self.logging.error(f'KeepAlive.d: NO_RESOLUTION for {url}')
            self.ping_results.append(False)

    def healthcheck(self):
        self.get_network_status()

        if self.software_radio == 'On':
            if self.ap_current_status in self.ap_disconnected_status:
                
                self.get_network_interfaces()
                if len(self.iface_a.name()) == 0:
                    raise AssertionError('No network interfaces available')
                
                self.failover()

            elif self.ap_current_status is None:
                '''TODO: Enable Network Interface from Device Manager'''
                pass

            elif self.ap_current_status == 'connected':
                pass

            elif not any(self.ping_results):
                self.failover()

            else:
                self.logging.error('Unknown AP or Interface error occurred')

        elif self.software_radio == 'Off' or self.software_radio is None:
            '''TODO: Turn ON network interface'''
            pass

    def failover(self):
        if self.current_ap_name is not None:

            if self.current_ap_name == creds.ap_b:
                target_ap = creds.ap_a
            elif self.current_ap_name == creds.ap_a:
                target_ap = creds.ap_b

        elif self.current_ap_name is None:
            target_ap = random.choice([creds.ap_a, creds.ap_b])

        self.connect_ap(self.iface_a, target_ap)
        self.logging.info(f'Failover {self.current_ap_name} -> {target_ap}')

    def georedundancy(self):
        while True:
            try:
                self.keepalived(mode='start')
                self.healthcheck()
                self.keepalived(mode='stop')

            except Exception as e:
                self.logging.error(f'Unknown {e}')

    def test(self):
        self.get_network_interfaces()
        self.get_networks_list(self.iface_a)

        # if self.current_ap_name is not None:

        #     if self.current_ap_name == creds.ap_b:
        #         target_ap = creds.ap_a
        #     elif self.current_ap_name == creds.ap_a:
        #         target_ap = creds.ap_b

        # elif self.current_ap_name is None:
        #     target_ap = random.choice([creds.ap_a, creds.ap_b])

        self.list_ap_attrs()

        # self.connect_ap(self.iface_a, target_ap)
        # self.logging.info(f'Failover {self.current_ap_name} -> {target_ap}')

wg = Geored_Wifi_Server()
# wg.georedundancy()
wg.test()
