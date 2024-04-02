import pywifi
import time

class Geored_Wifi_Server:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()

    def get_network_interfaces(self):
        'Interfaces (ifs) is a list of objects with the attribute ifs.name'
        self.ifaces = self.wifi.interfaces() 
        ifs = self.ifaces

        for u, w in enumerate(ifs):
            print(f'iface {u}:', w.name())

        return ifs

    def connect_available_iface(self):
        return
    
    def connect_available_network(self):
        return
    
    def list_bss_attrs(self, bss):
        for i in bss:
            bssid = i.bssid
            ssid  = i.ssid
            signal = i.signal
            freq = i.freq
            auth = 'Authorized' if i.auth == [] else 'Unauthorized'
            akm = i.akm
            print(f'{bssid}: {ssid}', signal, freq,  auth, akm)

    def get_networks_list(self, iface):
        '''
        Service Set (bss) attributes are bssid, ssid, freq, auth, akm, signal

        TODO:
         - Check if it gets connected automatically to each AP '''
        iface.scan()
        time.sleep(0.5)
        aps = iface.scan_results()

        self.list_bss_attrs(aps)

        return aps
    

wg = Geored_Wifi_Server()
ifs = wg.get_network_interfaces()
aps = wg.get_networks_list(ifs[0])