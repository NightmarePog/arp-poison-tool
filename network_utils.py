# network_utils.py - TODO LIST

# 1. TODO: Importovat potřebné moduly ze Scapy (ARP, Ether, srp)
# 2. TODO: Importovat modul 'os' pro práci se systémem

# 3. TODO: Funkce get_mac(ip)
#    - Musí poslat ARP broadcast do sítě.
#    - Musí vytáhnout MAC adresu z odpovědi.
#    - Musí vrátit MAC jako string (text).

# 4. TODO: Funkce toggle_forwarding(enable=True)
#    - Pokud enable=True, zapsat "1" do /proc/sys/net/ipv4/ip_forward
#    - Pokud enable=False, zapsat "0" (uklidit po sobě).
#    - Tip: Použij os.system() nebo os.popen().