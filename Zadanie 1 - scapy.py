from scapy.all import *
import os
import struct
import sys
import datetime
from collections import Counter

def zaciatokFunkcie(funkcia, zac):
    text = ""
    if zac == True:
        text = "# Zaciatok funkcie {} #".format(funkcia)
    else:
        text = "# Koniec funkcie {} #".format(funkcia)

    ram = "#" * (len(text))

    print(ram)
    print(text)
    print(ram)

def vlastnyHexdump(bytes):
    n = 0
    for a in bytes:
        n += 1
        if n % 16 == 0:
            print("{:02x}".format(a))
        elif n % 8 == 0:
            print("{:02x}".format(a), end="  ")
        else:
            print("{:02x}".format(a), end=" ")
    n = 0

def cesta(relCesta = ""):
    zaciatokFunkcie(cesta.__name__, True)

    dirname = os.path.dirname(__file__)
    # filename = os.path.join(dirname, 'vzorky_pcap_na_analyzu/eth-8.pcap')
    #filename = os.path.join(dirname, 'vzorky_pcap_na_analyzu/trace-24.pcap')
    #print(dirname)
    #print(type(dirname))
    return(os.path.join(dirname, relCesta))
    # return dirname + "/" + relCesta
    #return(os.path.join(dirname, 'vzorky_pcap_na_analyzu/trace-24.pcap'))

    zaciatokFunkcie(cesta.__name__, False)

def cestakSuboru():
    zaciatokFunkcie(cestakSuboru.__name__, True)

    path = cesta("zoznamSuborov.txt")
    #print(path)
    s = open(path, "r")
    zoznam = s.readlines()
    s.close()

    for number, line in enumerate(zoznam, 1):
        print("{:03}: {}".format(number, line), end="")

    print("Stlac -1 pre ukoncenie programu, 0 pre zadanie vlastnej cesty alebo vyber cislo suboru od 1 do ",
          len(zoznam))

    while True:
        vyber = int(input())
        # vyber = 3               # kratky vzorovy vstup
        # vyber = 25              # najvacsi vzorovy vstup
        # vyber = 30              # obsahuje RAW
        # vyber = 36              # obsahuje SNAP
        # vyber = 37              # obsahuje IP hlavicky s dlzkou inou ako 20
        # vyber = 10              # Kratky subor s ARP
        # vyber = 29              # LLC, RAW, ARP, TCP/IP
        # vyber = 28              # TELNET
        # vyber = 5               # SSH
        # vyber = 19              # Vypis flagov od spoluziaka
        # vyber = 1               # Obsahuje RST
        # vyber = 2


        if(vyber == -1):
            print("Koniec programu")
            return
        elif(vyber == 0):
            print("Zadaj vlastnu relativnu cestu k suboru:")
            vlastnaCesta = input()
            return cesta(vlastnaCesta)
        elif(vyber > 0 and vyber <= len(zoznam)):
            return cesta((zoznam[vyber - 1])[:-1])

        print("Nespravna volba, zadaj znova:")

    zaciatokFunkcie(cestakSuboru.__name__, False)

def protokolSubor():
    hexDict = {}
    meno = ""
    with open(cesta('protokoly.txt'), 'r') as prot:
        for l in prot:
            if l.startswith("#"):
                split = l.split()
                meno = split[0][1:]                 # bez znaku #
                continue
            (cislo, nazov) = l.split(" ", 1)        # max pocet splitov je 1, lebo po cisle nasleduje nazov, ktory je vcelku

            # cislo2 = int(cislo, 16)
            # print(type(cislo2))
            # print("{:04x}".format(cislo2))
            # hexDict[int(cislo, 16)] = nazov
            # print(meno, int(cislo, 16), nazov)

            hexDict[meno, int(cislo, 16)] = nazov[:-1]
    return hexDict

# def riadic():
#     zaciatokFunkcie(riadic.__name__, True)
#     while(True):
#         print("Zvol 0 pre vyber ineho pcap suboru")
#         print("Zvol 1 pre vypis podla bodu 1")
#         print("Zvol 3 pre vypis podla bodov 1-2-3 spolu")
#         print("Zvol 4 pre vypis podla bodu 4 a) - HTTP")
#         print("Zvol 5 pre vypis podla bodu 4 b) - HTTPS")
#         print("Zvol 6 pre vypis podla bodu 4 c) - TELNET")
#         print("Zvol 7 pre vypis podla bodu 4 d) - SSH")
#         print("Zvol 8 pre vypis podla bodu 4 e) - FTP riadiace")
#         print("Zvol 9 pre vypis podla bodu 4 f) - FTP dátové")
#         print("Zvol 10 pre vypis podla bodu 4 g) - TFTP")
#         print("Zvol 11 pre vypis podla bodu 4 h) - ICMP")
#         print("Zvol 12 pre vypis podla bodu 4 i) - ARP dvojice")
#         vyber = int(input())
#
#         if (vyber <= 12 and vyber >= 3) or vyber == 1 or vyber == 0:
#             break
#         else:
#             print("Nespravna volba, opakuj vyber")
#
#     pismeno = ""
#     if vyber == 4:
#         pismeno = "a"
#     if vyber == 5:
#         pismeno = "b"
#     if vyber == 6:
#         pismeno = "c"
#     if vyber == 7:
#         pismeno = "d"
#     if vyber == 8:
#         pismeno = "e"
#     if vyber == 9:
#         pismeno = "f"
#     if vyber == 10:
#         pismeno = "g"
#     if vyber == 11:
#         pismeno = "h"
#     if vyber == 12:
#         pismeno = "i"
#
#     return vyber, pismeno
#     zaciatokFunkcie(riadic.__name__, False)

# def uloha1(rawPacketList):
#     zaciatokFunkcie(uloha1.__name__, True)
#
#     # sumRamcov = 0
#
#     raw = False
#     snap = False
#     LLC = False
#     Ethernet = False
#
#     ramec = 1
#     for item in rawPacketList:
#         print("rámec", ramec)
#         ramec += 1
#
#         # print(type(item))
#         # print(item)
#
#         # break
#
#         dlzkaAPI = len(item)
#         dlzkaMedium = dlzkaAPI + 4
#         if dlzkaMedium < 64:
#             dlzkaMedium = 64
#
#         print("Dĺžka rámca poskytnutá pcap API – {} B".format(dlzkaAPI))
#         print("Dĺžka rámca prenášaného po médiu – {} B".format(dlzkaMedium))
#
#         # print("Velkost ramca na disku je ", sys.getsizeof(item))
#         # sumRamcov += sys.getsizeof(item)
#
#         # print("Typ rámca:", end=" ")
#         # if item[12:13] < b'\x06':
#         #     # print("{} {}".format(item[12:13], b'\x06'))
#         #     if item[14:15] == b'\xFF':
#         #         print("Novell 802.3 RAW")
#         #     elif item[14:15] == b'\xAA':
#         #         print("IEEE 802.3 LLC + SNAP")
#         #     else:
#         #         print("IEEE 802.3 LLC")
#         # else:
#         #     print("Ethernet II")
#
#         print("Typ rámca:", end=" ")
#         if item[12] < 0x06:
#             if item[14] == 0xFF:
#                 print("Novell 802.3 RAW")
#                 raw = True
#             elif item[14] == 0xAA:
#                 print("IEEE 802.3 LLC + SNAP")
#                 snap = True
#             else:
#                 print("IEEE 802.3 LLC")
#                 LLC = True
#         else:
#             print("Ethernet II")
#             Ethernet = True
#
#
#         print("Zdrojová MAC adresa:", " ".join("{:02X}".format(x) for x in item[6:12]))
#         print("Cieľová MAC adresa:", " ".join("{:02X}".format(x) for x in item[0:6]))
#
#
#         # vlastnyHexdump(item)
#         # print("\n")
#         # hexdump(item)
#         print("")
#
#     # print("Cely subor ma {} b".format(sumRamcov))
#     print("RAW", raw)
#     print("SNAP", snap)
#     print("LLC", LLC)
#     print("Ethernet", Ethernet)
#
#     zaciatokFunkcie(uloha1.__name__, False)

def zistiPortProtokolu(hexDict, pismeno):
    if pismeno == "a":
        for cislo, nazov in hexDict.items():
            if nazov == "HTTP":
                return cislo[1]
    if pismeno == "b":
        for cislo, nazov in hexDict.items():
            if nazov == "HTTPS":
                return cislo[1]
    if pismeno == "c":
        for cislo, nazov in hexDict.items():
            if nazov == "TELNET":
                return cislo[1]
    if pismeno == "d":
        for cislo, nazov in hexDict.items():
            if nazov == "SSH":
                return cislo[1]
    if pismeno == "e":
        for cislo, nazov in hexDict.items():
            if nazov == "FTP CONTROL":
                return cislo[1]
    if pismeno == "f":
        for cislo, nazov in hexDict.items():
            if nazov == "FTP DATA":
                return cislo[1]
    if pismeno == "g":
        for cislo, nazov in hexDict.items():
            if nazov == "TFTP":
                return cislo[1]
    if pismeno == "h":
        for cislo, nazov in hexDict.items():
            if nazov == "ICMP":
                return cislo[1]
    if pismeno == "i":
        for cislo, nazov in hexDict.items():
            if nazov == "ARP":
                return cislo[1]

def riadic():
    zaciatokFunkcie(riadic.__name__, True)
    while(True):
        print("Zvol 0 pre vyber ineho pcap suboru")
        print("Zvol 1 pre vypis podla bodu 1")
        print("Zvol 3 pre vypis podla bodov 1-2-3 spolu")
        print("Zvol 4 pre ulohu 4, zvol bod ulohy 4 a-i, zvol 0 ci vypisat iba ramce alebo 1 pre prvu kompletnu a prvu nekompletnu komunikaciu")

        vyber = input("Zadaj cisla [0,1,3] alebo vstup vo formate [4] [a-i] [0-1] ")

        vyber4 = ""
        rozsah = [chr(i) for i in range(ord("a"), ord("j"))]

        if len(vyber) == 1:
            if vyber != "0" and vyber != "1" and vyber != "3":
                print("Nespravna volba, opakuj vyber")
                continue
            return vyber
        elif len(vyber) == 5:
            vyber4 = vyber.split(" ")
            if vyber4[0] != "4" or vyber4[1] not in rozsah or (vyber4[2] != "0" and vyber4[2] != "1"):
                print("Nespravna volba, opakuj vyber")
                continue
            return vyber4
        else:
            print("Nespravna volba, opakuj vyber")
            continue

        print(vyber)


    zaciatokFunkcie(riadic.__name__, False)

def syn(flag):
    # presna zhoda
    if flag == 0x02:
        return True
    return False

def synack(flag):
    # presna zhoda
    if flag == 0x12:
        return True
    return False

def ack(flag):
    # presna zhoda
    if flag == 0x10:
        return True
    return False

def fin(flag):
    # kontrola iba fin, volna zhoda
    if flag >> 0 & 1 == 1:
        return True
    return False

def ackfin(flag):
    # kontrola iba fin a iba ack, volna zhoda
    if flag >> 0 & 1 == 1 and flag >> 4 & 1 == 1:
        return True
    return False

def rst(flag):
    # kontrola iba rst, volna zhoda
    if flag >> 2 & 1 == 1:
        return True
    return False

def otvorenieKomunikacie(flag_z0, flag_z1, flag_z2):
    if syn(flag_z0) and synack(flag_z1) and ack(flag_z2):
        # print("Komunikacia otvorena")
        return True
    return False

def zatvorenieKomunikacie(flag_k1, flag_k2, flag_k3, flag_k4, zaznam):
    if (ack(flag_k1) and fin(flag_k2) and ack(flag_k3) and fin(flag_k4)):
        # FIN ACK FIN ACK
        return True
    if rst(flag_k1) or rst(flag_k2):
        # RST
        return True
    if (ack(flag_k1) and  ackfin(flag_k2) and fin(flag_k3)):
        # FIN ACKFIN ACK
        return True
    if (ack(flag_k1) and ack(flag_k2) and fin(flag_k3) and fin(flag_k4)):
        # FIN FIN ACK ACK
        return True

    return False

# Todo
# Trace 6 ramec 566 jeden FIN je skor ako dalsi, prepisat cele overenie zatvorenia do samostatnej funkcie
# if (ack(flag_k1) and fin(flag_k2) and ack(flag_k3) and fin(flag_k4)) or rst(flag_k1):
#     print("Komunikacia zatvorena")

def uloha1(rawPacketList):
    '''
    Vypis dlzok ramca, typu ramca a MAC adries podla poziadaviek bodu 1 v zadani. Najpomalsou castou funkcie je
    hexdump() vypis.
    '''
    # zaciatokFunkcie(uloha1.__name__, True)

    ramec = 1
    for item in rawPacketList:
        print("rámec", ramec)
        ramec += 1

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        print("Dĺžka rámca poskytnutá pcap API – {} B".format(dlzkaAPI))
        print("Dĺžka rámca prenášaného po médiu – {} B".format(dlzkaMedium))

        print("Typ rámca:", end=" ")
        if item[12] < 0x06:
            if item[14] == 0xFF:
                print("Novell 802.3 RAW")
            elif item[14] == 0xAA:
                print("IEEE 802.3 LLC + SNAP")
            else:
                print("IEEE 802.3 LLC")
        else:
            print("Ethernet II")

        print("Zdrojová MAC adresa:", " ".join("{:02X}".format(x) for x in item[6:12]))
        print("Cieľová MAC adresa:", " ".join("{:02X}".format(x) for x in item[0:6]))

        # vlastnyHexdump(item)
        # print("\n")

        hexdump(item)
        print()

    # zaciatokFunkcie(uloha1.__name__, False)

def uloha2(rawPacketList, hexDict):
    zaciatokFunkcie(uloha2.__name__, True)

    ramec = 1
    for item in rawPacketList:
        print("rámec", ramec)
        ramec += 1

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        print("Dĺžka rámca poskytnutá pcap API – {} B".format(dlzkaAPI))
        print("Dĺžka rámca prenášaného po médiu – {} B".format(dlzkaMedium))

        print("Typ rámca:", end=" ")
        if item[12] < 0x06:
            if item[14] == 0xFF:
                print("Novell 802.3 RAW")
                print("IPX")
            elif item[14] == 0xAA:
                print("IEEE 802.3 LLC + SNAP")
                num2021 = 256 * item[20] + item[21]
                try:
                    print(hexDict['Ethertypes', num2021])
                except KeyError:
                    print("Neznámy Ethertype 0x{:04x}".format(num2021))
            else:
                print("IEEE 802.3 LLC")
                try:
                    print("DSAP", hexDict['SAPs', item[14]])
                    print("SSAP", hexDict['SAPs', item[15]])
                except KeyError:
                    print("Neznámy SAP 0x{:02x}".format(item[14]))
        else:
            print("Ethernet II")
            num1213 = 256 * item[12] + item[13]
            try:
                print(hexDict['Ethertypes', num1213])
            except KeyError:
                print("Neznámy Ethertype 0x{:04x}".format(num1213))


        print("Zdrojová MAC adresa:", " ".join("{:02X}".format(x) for x in item[6:12]))
        print("Cieľová MAC adresa:", " ".join("{:02X}".format(x) for x in item[0:6]))

        # vlastnyHexdump(item)
        # print("\n")
        hexdump(item)
        print("")

    zaciatokFunkcie(uloha2.__name__, False)

def uloha3(rawPacketList, hexDict):
    zaciatokFunkcie(uloha3.__name__, True)

    ramec = 1
    # prijimajuceUzly = []
    prijimajuceUzly = Counter()
    etherII = False
    for item in rawPacketList:
        etherII = False
        print("rámec", ramec)
        ramec += 1

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        print("Dĺžka rámca poskytnutá pcap API – {} B".format(dlzkaAPI))
        print("Dĺžka rámca prenášaného po médiu – {} B".format(dlzkaMedium))

        print("Typ rámca:", end=" ")
        if item[12] < 0x06:
            if item[14] == 0xFF:
                print("Novell 802.3 RAW")
                print("IPX")
            elif item[14] == 0xAA:
                print("IEEE 802.3 LLC + SNAP")
                num2021 = 256 * item[20] + item[21]
                try:
                    print(hexDict['Ethertypes', num2021])
                except KeyError:
                    print("Neznámy Ethertype 0x{:04x}".format(num2021))
            else:
                print("IEEE 802.3 LLC")
                try:
                    print("DSAP", hexDict['SAPs', item[14]])
                    print("SSAP", hexDict['SAPs', item[15]])
                except KeyError:
                    print("Neznámy SAP 0x{:02x}".format(item[14]))
        else:
            print("Ethernet II")
            etherII = True

        print("Zdrojová MAC adresa:", " ".join("{:02X}".format(x) for x in item[6:12]))
        print("Cieľová MAC adresa:", " ".join("{:02X}".format(x) for x in item[0:6]))

        dlhOffset = 14
        # 14b pre DLH

        ipv4 = False
        arp = False

        ipOffset = 0
        tcp = False
        udp = False
        icmp = False

        if etherII:
            num1213 = 256 * item[12] + item[13]
            try:
                print(hexDict['Ethertypes', num1213])
            except KeyError:
                print("Neznámy Ethertype 0x{:04x}".format(num1213))
            if num1213 == 0x0806:
                # Toto je analyza ARP natvrdo. Co ak sa zmeni kod IPv4?
                arp = True
                try:
                    print(hexDict['ARP', item[21]])
                except KeyError:
                    print("Neznáma ARP operácia {}".format(item[21]))
                print("zdrojová hardvérová adresa:", " ".join("{:02X}".format(x) for x in item[22:28]))
                print("zdrojová protokolová adresa:", ".".join("{}".format(x) for x in item[28:32]))
                print("cieľová hardvérová adresa:", " ".join("{:02X}".format(x) for x in item[32:38]))
                print("cieľová protokolová adresa:", ".".join("{}".format(x) for x in item[38:42]))

            if num1213 == 0x0800:
                # Toto je analyza IPv4 natvrdo. Co ak sa zmeni kod IPv4?
                ipv4 = True
                print("zdrojová IP adresa:", ".".join("{}".format(x) for x in item[26:30]))
                print("cieľová IP adresa:", ".".join("{}".format(x) for x in item[30:34]))
                # prijimajuceUzly.append(item[30:34])
                if prijimajuceUzly[item[30:34]] == 0:
                    prijimajuceUzly[item[30:34]] = 1
                else:
                    prijimajuceUzly[item[30:34]] += 1

                try:
                    print(hexDict['IP', item[23]])
                except KeyError:
                    print("Neznamy IP protokol {}".format(item[23]))

                if item[23] == 0x06:
                    # Ak je to TCP tak sa bude pokracovat
                    tcp = True
                if item[23] == 0x11:
                    udp = True
                if item[23] == 0x01:
                    icmp = True

                ipOffset = dlhOffset + (item[14] % 16) * 4
                # print(ipOffset)

        if tcp and ipv4:
            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]

            if srcPort < dstPort:
                try:
                    print(hexDict['TCP', srcPort])
                except KeyError:
                    print("Nerozpoznaný port")
            else:
                try:
                    print(hexDict['TCP', dstPort])
                except KeyError:
                    print("Nerozpoznaný port")

            print("zdrojový port:", srcPort)
            print("cieľový port:", dstPort)

        if udp and ipv4:
            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]

            if srcPort < dstPort:
                try:
                    print(hexDict['UDP', srcPort])
                except KeyError:
                    print("Nerozpoznaný port")
            else:
                try:
                    print(hexDict['UDP', dstPort])
                except KeyError:
                    print("Nerozpoznaný port")

            print("zdrojový port:", srcPort)
            print("cieľový port:", dstPort)

        if icmp and ipv4:
            type = item[ipOffset]
            try:
                print(hexDict['ICMP', type])
            except KeyError:
                print("Nerozpoznaný typ")


        # vlastnyHexdump(item)
        # print("\n")
        hexdump(item)
        print()

    print("IP adresy prijímajúcich uzlov:")
    for i in prijimajuceUzly:
        print(".".join("{}".format(x) for x in i))
    print("Adresa uzla s najväčším počtom prijatých paketov:")
    najpocetnejsi = prijimajuceUzly.most_common(1)
    # print(najpocetnejsi)
    print(".".join("{}".format(x) for x in najpocetnejsi[0][0]), "{} paketov".format(najpocetnejsi[0][1]))
    # print(sys.getsizeof(prijimajuceUzly))

    # pocty = Counter(prijimajuceUzly)
    # print(type(pocty))
    # print(pocty)
    # for i in pocty:
    #     print(i)
    #     # print(".".join("{}".format(x) for x in i), pocty[i])
    zaciatokFunkcie(uloha3.__name__, False)

# def konkretnePaketyPreTCP(rawPacketList, hexDict, zoznam):
#     zaciatokFunkcie(konkretnePakety.__name__, True)
#
#     ramec = 0
#     etherII = False
#
#     for item in rawPacketList:
#         etherII = False
#
#         sprava = "rámec {}\n".format(zoznam[ramec])
#
#         ramec += 1
#
#         dlzkaAPI = len(item)
#         dlzkaMedium = dlzkaAPI + 4
#         if dlzkaMedium < 64:
#             dlzkaMedium = 64
#
#         sprava += "Dĺžka rámca poskytnutá pcap API – {} B\n".format(dlzkaAPI)
#         sprava += "Dĺžka rámca prenášaného po médiu – {} B\n".format(dlzkaMedium)
#         sprava += "Ethernet II\n"
#         etherII = True
#         sprava += "Zdrojová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[6:12]) + "\n"
#         sprava += "Cieľová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[0:6]) + "\n"
#
#         dlhOffset = 14
#
#         ipv4 = False
#
#         ipOffset = 0
#         tcp = False
#
#
#         if etherII:
#             num1213 = 256 * item[12] + item[13]
#             try:
#                 sprava += "{}\n".format(hexDict['Ethertypes', num1213])
#             except KeyError:
#                 sprava += "Neznámy Ethertype 0x{:04x}\n".format(num1213)
#
#             if num1213 == 0x0800:
#                 # Toto je analyza IPv4 natvrdo. Co ak sa zmeni kod IPv4?
#                 ipv4 = True
#                 sprava += "zdrojová IP adresa: " + ".".join("{}".format(x) for x in item[26:30]) + "\n"
#                 sprava += "cieľová IP adresa: " + ".".join("{}".format(x) for x in item[30:34]) + "\n"
#
#                 try:
#                     sprava += "{}\n".format(hexDict['IP', item[23]])
#                 except KeyError:
#                     sprava += "Neznamy IP protokol {}\n".format(item[23])
#
#                 if item[23] == 0x06:
#                     # Ak je to TCP tak sa bude pokracovat
#                     tcp = True
#                 if item[23] == 0x11:
#                     udp = True
#                 if item[23] == 0x01:
#                     icmp = True
#
#                 ipOffset = dlhOffset + (item[14] % 16) * 4
#                 # print(ipOffset)
#
#         if tcp and ipv4:
#             srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
#             dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]
#
#             mensi = min(srcPort, dstPort)
#
#             try:
#                 sprava += "{}\n".format(hexDict['TCP', mensi])
#             except KeyError:
#                 sprava += "Nerozpoznaný port\n"
#
#             sprava += "zdrojový port: {}\n".format(srcPort)
#             sprava += "cieľový port: {}\n".format(dstPort)
#
#             print(sprava, end="")
#             hexdump(item)
#             print()
#
#
#
#     zaciatokFunkcie(konkretnePakety.__name__, False)

def konkretnePakety(rawPacketList, hexDict, zoznam):
    zaciatokFunkcie(uloha4.__name__, True)

    ramec = 0
    tftpPorty = []
    prijimajuceUzly = Counter()
    etherII = False

    for item in rawPacketList:
        etherII = False

        sprava = "rámec {}\n".format(zoznam[ramec])

        ramec += 1

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        sprava += "Dĺžka rámca poskytnutá pcap API – {} B\n".format(dlzkaAPI)
        sprava += "Dĺžka rámca prenášaného po médiu – {} B\n".format(dlzkaMedium)

        sprava += "Typ rámca: "
        if item[12] < 0x06:
            if item[14] == 0xFF:
                sprava += "Novell 802.3 RAW\nIPX\n"
            elif item[14] == 0xAA:
                sprava += "IEEE 802.3 LLC + SNAP\n"
                num2021 = 256 * item[20] + item[21]
                try:
                    sprava += "{}\n".format(hexDict['Ethertypes', num2021])
                except KeyError:
                    sprava += "Neznámy Ethertype 0x{:04x}\n".format(num2021)
            else:
                sprava += "IEEE 802.3 LLC\n"
                try:
                    sprava += "DSAP {}\n".format(hexDict['SAPs', item[14]])
                    sprava += "SSAP {}\n".format(hexDict['SAPs', item[15]])
                except KeyError:
                    sprava += "Neznámy SAP 0x{:02x}\n".format(item[14])
        else:
            sprava += "Ethernet II\n"
            etherII = True

        sprava += "Zdrojová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[6:12]) + "\n"
        sprava += "Cieľová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[0:6]) + "\n"

        dlhOffset = 14
        # 14b pre DLH

        ipv4 = False
        arp = False

        ipOffset = 0
        tcp = False
        udp = False
        icmp = False

        if etherII:
            num1213 = 256 * item[12] + item[13]
            try:
                sprava += "{}\n".format(hexDict['Ethertypes', num1213])
            except KeyError:
                sprava += "Neznámy Ethertype 0x{:04x}\n".format(num1213)
            if num1213 == 0x0806:
                # Toto je analyza ARP natvrdo. Co ak sa zmeni kod IPv4?
                arp = True
                try:
                    sprava += "{}\n".format(hexDict['ARP', item[21]])
                except KeyError:
                    sprava += "Neznáma ARP operácia {}\n".format(item[21])

                sprava += "zdrojová hardvérová adresa: " + " ".join("{:02X}".format(x) for x in item[22:28]) + "\n"
                sprava += "zdrojová protokolová adresa: " + ".".join("{}".format(x) for x in item[28:32]) + "\n"
                sprava += "cieľová hardvérová adresa: " + " ".join("{:02X}".format(x) for x in item[32:38]) + "\n"
                sprava += "cieľová protokolová adresa: " + ".".join("{}".format(x) for x in item[38:42]) + "\n"

                print(sprava, end="")
                hexdump(item)
                print()

            if num1213 == 0x0800:
                # Toto je analyza IPv4 natvrdo. Co ak sa zmeni kod IPv4?
                ipv4 = True
                sprava += "zdrojová IP adresa: " + ".".join("{}".format(x) for x in item[26:30]) + "\n"
                sprava += "cieľová IP adresa: " + ".".join("{}".format(x) for x in item[30:34]) + "\n"
                # prijimajuceUzly.append(item[30:34])
                if prijimajuceUzly[item[30:34]] == 0:
                    prijimajuceUzly[item[30:34]] = 1
                else:
                    prijimajuceUzly[item[30:34]] += 1

                try:
                    sprava += "{}\n".format(hexDict['IP', item[23]])
                except KeyError:
                    sprava += "Neznamy IP protokol {}\n".format(item[23])

                if item[23] == 0x06:
                    # Ak je to TCP tak sa bude pokracovat
                    tcp = True
                if item[23] == 0x11:
                    udp = True
                if item[23] == 0x01:
                    icmp = True

                ipOffset = dlhOffset + (item[14] % 16) * 4
                # print(ipOffset)

        if tcp and ipv4:
            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]

            mensi = min(srcPort, dstPort)

            try:
                sprava += "{}\n".format(hexDict['TCP', mensi])
            except KeyError:
                sprava += "Nerozpoznaný port\n"

            sprava += "zdrojový port: {}\n".format(srcPort)
            sprava += "cieľový port: {}\n".format(dstPort)

            print(sprava, end="")
            hexdump(item)
            print()


        # if udp and ipv4:
        #     srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
        #     dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]
        #
        #     porty = [srcPort, dstPort]
        #     porty.sort()
        #
        #     if dstPort == 0x45:
        #         tftpPorty.append(porty)
        #     else:
        #         for zaznam in tftpPorty:
        #             # if srcPort in zaznam and dstPort not in zaznam:
        #             #     if srcPort == zaznam[0]:
        #             #         zaznam[1] = dstPort
        #             #     else:
        #             #         zaznam[0] = dstPort
        #             if dstPort in zaznam and srcPort not in zaznam:
        #                 if dstPort == zaznam[0] and zaznam[1] == 0x45:
        #                     zaznam[1] = srcPort
        #                 elif zaznam[0] == 0x45:
        #                     zaznam[0] = srcPort
        #                 zaznam.sort()
        #
        #
        #
        #     mensi = min(srcPort, dstPort)
        #
        #     try:
        #         sprava += "{}\n".format(hexDict['UDP', mensi])
        #     except KeyError:
        #         if porty in tftpPorty:
        #             sprava += "TFTP\n"
        #         else:
        #             sprava += "Nerozpoznaný port\n"
        #
        #     sprava += "zdrojový port: {}\n".format(srcPort)
        #     sprava += "cieľový port: {}\n".format(dstPort)
        #
        #     # if prepinac == "g" and mensi == 0x45:
        #     #     print(sprava, end="")
        #     #     hexdump(item)
        #     #     print()
        #
        #     if prepinac == "g" and porty in tftpPorty:
        #         if dstPort == 0x45:
        #             sprava = "Komunikacia {}\n".format(tftpPorty.index(porty) + 1) + sprava
        #         print(sprava, end="")
        #         hexdump(item)
        #         print()
        #
        #
        #     # print("TFTP zoznam zoznamov", tftpPorty)

        if icmp and ipv4:
            type = item[ipOffset]
            try:
                sprava += "{}\n".format(hexDict['ICMP', type])
            except KeyError:
                sprava += "Nerozpoznaný typ\n"

            print(sprava, end="")
            hexdump(item)
            print()



    zaciatokFunkcie(uloha4.__name__, False)


def komunikacie(rawPacketList, hexDict, zadanyPort = None, ibaPrva = False):
    zaciatokFunkcie(komunikacie.__name__, True)

    ramec = 1

    etherII = False
    vypisICMP = False
    vypisTCP = False
    vypisARP = False

    komunikacieDict = {}
    for item in rawPacketList:
        etherII = False

        if item[12] < 0x06:
            if item[14] == 0xFF:
                pass
            elif item[14] == 0xAA:
                pass
            else:
                pass
        else:
            etherII = True

        dlhOffset = 14
        # 14b pre DLH

        ipv4 = False
        arp = False

        ipOffset = 0
        tcp = False
        udp = False
        icmp = False

        if etherII:
            num1213 = 256 * item[12] + item[13]

            if num1213 == 0x0800:
                # Toto je analyza IPv4 natvrdo. Co ak sa zmeni kod IPv4?
                ipv4 = True

                if item[23] == 0x01 and zadanyPort == 0x01:
                    # Ak je to ICMP tak sa bude pokracovat
                    icmp = True
                elif item[23] == 0x06 and zadanyPort != 0x01 and zadanyPort != 0x0806:
                    # Ak je to TCP a zaroven nesledujem ICMP ani ARP, tak sa bude pokracovat
                    tcp = True
                    # print("Teraz")

                ipOffset = dlhOffset + (item[14] % 16) * 4

            if num1213 == 0x0806 and zadanyPort == 0x0806:
                # Toto je analyza ARP natvrdo. Co ak sa zmeni kod IPv4?
                arp = True
                vypisARP = True

        if tcp and ipv4:

            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]
            porty = [srcPort, dstPort]
            porty.sort()
            flag = item[ipOffset + 13]

            vypisTCP = True

            # print("ramec", ramec)
            # print("U", flag >> 5 & 1)
            # print("A", flag >> 4 & 1)
            # print("P", flag >> 3 & 1)
            # print("R", flag >> 2 & 1)
            # print("S", flag >> 1 & 1)
            # print("F", flag >> 0 & 1)
            # print()

            if zadanyPort == None:
                if (porty[0], porty[1]) not in komunikacieDict:
                    komunikacieDict[porty[0], porty[1]] = [(ramec, flag)]           # poradove cislo ramca
                else:
                    komunikacieDict[porty[0], porty[1]].append((ramec, flag))       # poradove cislo ramca
            elif porty[0] == zadanyPort:
                if (porty[0], porty[1]) not in komunikacieDict:
                    komunikacieDict[porty[0], porty[1]] = [(ramec, flag)]           # poradove cislo ramca
                else:
                    komunikacieDict[porty[0], porty[1]].append((ramec, flag))       # poradove cislo ramca

            # sn = item[ipOffset + 4] * 256 ** 3 + item[ipOffset + 5] * 256 ** 2 + item[ipOffset + 6] * 256 + item[ipOffset + 7]
            # an = item[ipOffset + 8] * 256 ** 3 + item[ipOffset + 9] * 256 ** 2 + item[ipOffset + 10] * 256 + item[ipOffset + 11]
            # mensi = min(srcPort, dstPort)
            # print("ramec {}\nTCP\nSP {}\nDP {}\nSN {}\nAN {}\nFL {}\n".format(ramec, srcPort, dstPort, sn, an, flag))

        if icmp and ipv4:
            type = item[ipOffset]

            srcIP = item[26:30]
            dstIP = item[30:34]

            vypisICMP = True

            komunikacieDict[ramec] = (srcIP, dstIP, type)

        if arp:
            SHA = item[22:28]
            SPA = item[28:32]
            THA = item[32:38]
            TPA = item[38:42]
            OPE = item[21]

            komunikacieDict[ramec] = (OPE, SHA, SPA, THA, TPA)

        ramec += 1

    if vypisTCP:
        otvorena = False
        zatvorena = False
        vsetky = []

        prvaUplna = None
        prvaUplnaSubList = []
        prvaUplnaSubListMap = None

        prvaNeuplna = None
        prvaNeuplnaSubList = []
        prvaNeuplnaSubListMap = None

        booleanUp = False
        booleanNeup = False

        # for k in komunikacieDict:
        #     print(k, komunikacieDict[k])
        # print("+" * 20)

        for k in komunikacieDict:
            otvorena = False
            zatvorena = False

            # print(k, komunikacieDict[k])

            if len(komunikacieDict[k]) >= 3:
                flag_z0 = komunikacieDict[k][0][1]
                flag_z1 = komunikacieDict[k][1][1]
                flag_z2 = komunikacieDict[k][2][1]

                if otvorenieKomunikacie(flag_z0, flag_z1, flag_z2):
                    # print("Komunikacia otvorena")
                    otvorena = True
                else:
                    # print("--------------------Neotvorena komunikacia")
                    pass

            if len(komunikacieDict[k]) >= 4:
                flag_k1 = komunikacieDict[k][-1][1]
                flag_k2 = komunikacieDict[k][-2][1]
                flag_k3 = komunikacieDict[k][-3][1]
                flag_k4 = komunikacieDict[k][-4][1]
                if zatvorenieKomunikacie(flag_k1, flag_k2, flag_k3, flag_k4, komunikacieDict[k]):
                    # print("Komunikacia zatvorena")
                    zatvorena = True
                else:
                    # print("--------------------Nezatvorena komunikacia")
                    pass

                if ibaPrva and otvorena and zatvorena and not booleanUp:
                    prvaUplna = [i[0] for i in komunikacieDict[k]]
                    for i in prvaUplna:
                        prvaUplnaSubList.append(rawPacketList[i - 1])
                    booleanUp = True
                    prvaUplnaSubListMap = prvaUplna
                elif ibaPrva and otvorena and zatvorena == False and not booleanNeup:
                    prvaNeuplna = [i[0] for i in komunikacieDict[k]]
                    for i in prvaNeuplna:
                        prvaNeuplnaSubList.append(rawPacketList[i - 1])
                    booleanNeup = True
                    prvaNeuplnaSubListMap = prvaNeuplna
                elif not ibaPrva:
                    pass
                    # Todo

                if booleanUp and booleanNeup:
                    # return prvaUplna, prvaNeuplna
                    print("Prva uplna komunikacia")
                    konkretnePakety(prvaUplnaSubList, hexDict, prvaUplnaSubListMap)
                    print("Prva neuplna komunikacia")
                    konkretnePakety(prvaNeuplnaSubList, hexDict, prvaNeuplnaSubListMap)
                    return
            else:
                pass
                # print("Prilis kratka komunikacia")

        # print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++Teraz")
        # print(prvaUplna, prvaUplnaSubListMap)
        # print(prvaNeuplna, prvaNeuplnaSubListMap)
        if ibaPrva:
            if prvaUplna == None:
                print("Ziadna uplna komunikacia nebola najdena")
            else:
                print("Prva uplna komunikacia")
                konkretnePakety(prvaUplnaSubList, hexDict, prvaUplnaSubListMap)
            if prvaNeuplna == None:
                print("Ziadna otvorena a nezatvorena komunikacia nebola najdena")
            else:
                print("Prva neuplna komunikacia")
                konkretnePakety(prvaNeuplnaSubList, hexDict, prvaNeuplnaSubListMap)

        return

        # print("Cely dict", sys.getsizeof(komunikacieDict))
        # print("Jeden kluc", sys.getsizeof(komunikacieDict[k]))
        # print("Zaznam kluca 0", sys.getsizeof(komunikacieDict[k][0]))
        # print("Zaznam cisla 0 kluca 0", sys.getsizeof(komunikacieDict[k][0][0]))
        # print("Zaznam cisla 1 kluca 0", sys.getsizeof(komunikacieDict[k][0][1]))

    if vypisICMP:
        print("Teraz ICMP")
        ipSrc1, ipDst1, ipSrc2, ipDst2, type1, type2, k1, k2 = None, None, None, None, None, None, None, None
        b = True
        cislo = 1

        for k in komunikacieDict:
            # print(k, komunikacieDict[k])
            # print(b)
            # if komunikacieDict[k][2] == 0 or komunikacieDict[k][2] == 8:
            if b:
                ipSrc1 = komunikacieDict[k][0]
                ipDst1 = komunikacieDict[k][1]
                type1 = komunikacieDict[k][2]
                k1 = k
                b = False
                # print("1", ipSrc1, ipDst1, type1)
            else:
                ipSrc2 = komunikacieDict[k][0]
                ipDst2 = komunikacieDict[k][1]
                type2 = komunikacieDict[k][2]
                k2 = k
                b = True
                # print("2", ipSrc2, ipDst2, type2)
                if type1 == 8 and type2 == 0 and ipSrc1 == ipDst2 and ipSrc2 == ipDst1:
                    print("Komunikacia c. {}".format(cislo))
                    cislo += 1
                    rawPacketSubList = []
                    rawPacketSubList.append(rawPacketList[k1-1])
                    rawPacketSubList.append(rawPacketList[k2-1])
                    zoznam = [k1, k2]

                    konkretnePakety(rawPacketSubList, hexDict, zoznam)
                    # print(k1, komunikacieDict[k1])
                    # print(k2, komunikacieDict[k2])

    if vypisARP:
        for a in komunikacieDict:
            print(a, komunikacieDict[a])

    zaciatokFunkcie(komunikacie.__name__, False)

def uloha4(rawPacketList, hexDict, prepinac):
    zaciatokFunkcie(uloha4.__name__, True)

    ramec = 1
    tftpPorty = []
    prijimajuceUzly = Counter()
    etherII = False

    for item in rawPacketList:
        etherII = False

        sprava = "rámec {}\n".format(ramec)

        ramec += 1

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        sprava += "Dĺžka rámca poskytnutá pcap API – {} B\n".format(dlzkaAPI)
        sprava += "Dĺžka rámca prenášaného po médiu – {} B\n".format(dlzkaMedium)

        sprava += "Typ rámca: "
        if item[12] < 0x06:
            if item[14] == 0xFF:
                sprava += "Novell 802.3 RAW\nIPX\n"
            elif item[14] == 0xAA:
                sprava += "IEEE 802.3 LLC + SNAP\n"
                num2021 = 256 * item[20] + item[21]
                try:
                    sprava += "{}\n".format(hexDict['Ethertypes', num2021])
                except KeyError:
                    sprava += "Neznámy Ethertype 0x{:04x}\n".format(num2021)
            else:
                sprava += "IEEE 802.3 LLC\n"
                try:
                    sprava += "DSAP {}\n".format(hexDict['SAPs', item[14]])
                    sprava += "SSAP {}\n".format(hexDict['SAPs', item[15]])
                except KeyError:
                    sprava += "Neznámy SAP 0x{:02x}\n".format(item[14])
        else:
            sprava += "Ethernet II\n"
            etherII = True

        sprava += "Zdrojová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[6:12]) + "\n"
        sprava += "Cieľová MAC adresa: " + " ".join("{:02X}".format(x) for x in item[0:6]) + "\n"

        dlhOffset = 14
        # 14b pre DLH

        ipv4 = False
        arp = False

        ipOffset = 0
        tcp = False
        udp = False
        icmp = False

        if etherII:
            num1213 = 256 * item[12] + item[13]
            try:
                sprava += "{}\n".format(hexDict['Ethertypes', num1213])
            except KeyError:
                sprava += "Neznámy Ethertype 0x{:04x}\n".format(num1213)
            if num1213 == 0x0806:
                # Toto je analyza ARP natvrdo. Co ak sa zmeni kod IPv4?
                arp = True
                try:
                    sprava += "{}\n".format(hexDict['ARP', item[21]])
                except KeyError:
                    sprava += "Neznáma ARP operácia {}\n".format(item[21])

                sprava += "zdrojová hardvérová adresa: " + " ".join("{:02X}".format(x) for x in item[22:28]) + "\n"
                sprava += "zdrojová protokolová adresa: " + ".".join("{}".format(x) for x in item[28:32]) + "\n"
                sprava += "cieľová hardvérová adresa: " + " ".join("{:02X}".format(x) for x in item[32:38]) + "\n"
                sprava += "cieľová protokolová adresa: " + ".".join("{}".format(x) for x in item[38:42]) + "\n"

                if prepinac == "i":
                    print(sprava, end="")
                    hexdump(item)
                    print()

            if num1213 == 0x0800:
                # Toto je analyza IPv4 natvrdo. Co ak sa zmeni kod IPv4?
                ipv4 = True
                sprava += "zdrojová IP adresa: " + ".".join("{}".format(x) for x in item[26:30]) + "\n"
                sprava += "cieľová IP adresa: " + ".".join("{}".format(x) for x in item[30:34]) + "\n"
                # prijimajuceUzly.append(item[30:34])
                if prijimajuceUzly[item[30:34]] == 0:
                    prijimajuceUzly[item[30:34]] = 1
                else:
                    prijimajuceUzly[item[30:34]] += 1

                try:
                    sprava += "{}\n".format(hexDict['IP', item[23]])
                except KeyError:
                    sprava += "Neznamy IP protokol {}\n".format(item[23])

                if item[23] == 0x06:
                    # Ak je to TCP tak sa bude pokracovat
                    tcp = True
                if item[23] == 0x11:
                    udp = True
                if item[23] == 0x01:
                    icmp = True

                ipOffset = dlhOffset + (item[14] % 16) * 4
                # print(ipOffset)

        if tcp and ipv4:
            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]

            mensi = min(srcPort, dstPort)

            try:
                sprava += "{}\n".format(hexDict['TCP', mensi])
            except KeyError:
                sprava += "Nerozpoznaný port\n"

            sprava += "zdrojový port: {}\n".format(srcPort)
            sprava += "cieľový port: {}\n".format(dstPort)

            if prepinac == "a" and mensi == 0x50:
                print(sprava, end="")
                hexdump(item)
                print()

            if prepinac == "b" and mensi == 0x1BB:
                print(sprava, end="")
                hexdump(item)
                print()

            if prepinac == "c" and mensi == 0x17:
                print(sprava, end="")
                hexdump(item)
                print()

            if prepinac == "d" and mensi == 0x16:
                print(sprava, end="")
                hexdump(item)
                print()

            if prepinac == "e" and mensi == 0x15:
                print(sprava, end="")
                hexdump(item)
                print()

            if prepinac == "f" and mensi == 0x14:
                print(sprava, end="")
                hexdump(item)
                print()


        if udp and ipv4:
            srcPort = item[ipOffset] * 256 + item[ipOffset + 1]
            dstPort = item[ipOffset + 2] * 256 + item[ipOffset + 3]

            porty = [srcPort, dstPort]
            porty.sort()

            if dstPort == 0x45:
                tftpPorty.append(porty)
            else:
                for zaznam in tftpPorty:
                    # if srcPort in zaznam and dstPort not in zaznam:
                    #     if srcPort == zaznam[0]:
                    #         zaznam[1] = dstPort
                    #     else:
                    #         zaznam[0] = dstPort
                    if dstPort in zaznam and srcPort not in zaznam:
                        if dstPort == zaznam[0] and zaznam[1] == 0x45:
                            zaznam[1] = srcPort
                        elif zaznam[0] == 0x45:
                            zaznam[0] = srcPort
                        zaznam.sort()



            mensi = min(srcPort, dstPort)

            try:
                sprava += "{}\n".format(hexDict['UDP', mensi])
            except KeyError:
                if porty in tftpPorty:
                    sprava += "TFTP\n"
                else:
                    sprava += "Nerozpoznaný port\n"

            sprava += "zdrojový port: {}\n".format(srcPort)
            sprava += "cieľový port: {}\n".format(dstPort)

            # if prepinac == "g" and mensi == 0x45:
            #     print(sprava, end="")
            #     hexdump(item)
            #     print()

            if prepinac == "g" and porty in tftpPorty:
                if dstPort == 0x45:
                    sprava = "Komunikacia {}\n".format(tftpPorty.index(porty) + 1) + sprava
                print(sprava, end="")
                hexdump(item)
                print()


            # print("TFTP zoznam zoznamov", tftpPorty)


        if icmp and ipv4:
            type = item[ipOffset]
            try:
                sprava += "{}\n".format(hexDict['ICMP', type])
            except KeyError:
                sprava += "Nerozpoznaný typ\n"

            if prepinac == "h":
                print(sprava, end="")
                hexdump(item)
                print()



    zaciatokFunkcie(uloha4.__name__, False)

def main():
    zaciatokFunkcie(main.__name__, True)

    origVystup = sys.stdout

    filename = cestakSuboru()

    while filename != None:

        print("Bola zvolena cesta ", filename)

        casCitanieZac = datetime.datetime.now()

        packets = rdpcap(filename)                  # musim pouzit raw
        # packets = RawPcapReader(filename)           # vracia tuple
        # packets = PcapReader(filename)              # vracia to iste ako rdpcap a tiez treba pouzit raw
        # packets = sniff(filename)                   # nefunguje

        # packetList = PacketList([p for p in packets])
        # rawPacketList = [raw(p) for p in packetList]

        casCitanieKon = datetime.datetime.now()

        print("Citanie suboru zabralo {} ms".format((casCitanieKon - casCitanieZac).total_seconds() * 1000))
        # print(type(packets))
        # print(packets[0])


        casPrepisuZac = datetime.datetime.now()
        rawPacketList = [raw(p) for p in packets]
        casPrepisuKon = datetime.datetime.now()
        print("Prepis suboru zabral {} ms".format((casPrepisuKon - casPrepisuZac).total_seconds() * 1000))

        casHexDictZac = datetime.datetime.now()
        hexDict = protokolSubor()
        casHexDictKon = datetime.datetime.now()
        print("Vytvaranie slovnika protokolov zabralo {} ms".format((casHexDictKon - casHexDictZac).total_seconds() * 1000))

        # prvaUplna, prvaNeuplna = komunikacie(rawPacketList, hexDict, 80, True)
        # print(prvaUplna)
        # print(prvaNeuplna)

        # komunikacie(rawPacketList, hexDict, 80, True)


        volby = riadic()
        while(volby != "0"):
            print("Bola zvlolena moznost", volby)
            outputFile = open(cesta('vystup.txt'), 'w')
            sys.stdout = origVystup

            if volby == "1":
                sys.stdout = outputFile
                casU1Zac = datetime.datetime.now()
                uloha1(rawPacketList)
                casU1Kon = datetime.datetime.now()
                sys.stdout = origVystup
                print("Funkcia uloha1() zabrala {} ms".format((casU1Kon - casU1Zac).total_seconds() * 1000))

            # sys.stdout = outputFile
            # casU2Zac = datetime.datetime.now()
            # uloha2(rawPacketList, hexDict)
            # casU2Kon = datetime.datetime.now()
            # sys.stdout = origVystup
            # print("Funkcia uloha2() zabrala {} ms".format((casU2Kon - casU2Zac).total_seconds() * 1000))

            if volby == "3":
                sys.stdout = outputFile
                casU3Zac = datetime.datetime.now()
                uloha3(rawPacketList, hexDict)
                casU3Kon = datetime.datetime.now()
                sys.stdout = origVystup
                print("Funkcia uloha3() zabrala {} ms".format((casU3Kon - casU3Zac).total_seconds() * 1000))

            if volby[0] == "4" and volby[2] == "0":
                sys.stdout = outputFile
                casU4Zac = datetime.datetime.now()
                uloha4(rawPacketList, hexDict, volby[1])
                casU4Kon = datetime.datetime.now()
                sys.stdout = origVystup
                print("Funkcia uloha4() zabrala {} ms".format((casU4Kon - casU4Zac).total_seconds() * 1000))
            elif volby[0] == "4" and volby[2] == "1":

                casU4KomZac = datetime.datetime.now()
                port = zistiPortProtokolu(hexDict, volby[1])
                if volby[1] == "g":
                    print("UDP nenadvazuje spojenia, preto nie je mozne vypisat komunikaciu ako pri TCP. Zvolte 4 g 0")
                # elif volby[1] == "h":
                #     print("ICMP nenadvazuje spojenia, preto nie je mozne vypisat komunikaciu ako pri TCP. Zvolte 4 h 0")
                # elif volby[1] == "i":
                #     print("ARP nenadvazuje spojenia, preto nie je mozne vypisat komunikacie ako pri TCP. Zvolte 4 i 0")
                else:
                    sys.stdout = outputFile
                    komunikacie(rawPacketList, hexDict, port, True)
                casU4KomKon = datetime.datetime.now()
                sys.stdout = origVystup
                print("Funkcia komunikacie() zabrala {} ms".format((casU4KomKon - casU4KomZac).total_seconds() * 1000))

            # print("packets {} {}".format(type(packets), sys.getsizeof(packets)))
            # print("packetList {} {}".format(type(packetList), sys.getsizeof(packetList)))
            # print("rawPacketList {} {}".format(type(rawPacketList), sys.getsizeof(rawPacketList)))

            # print(filename)

            outputFile.close()

            volby = riadic()

        # while(volby[0] != 0):
        #     outputFile = open(cesta('vystup.txt'), 'w')
        #     sys.stdout = origVystup
        #
        #
        #     # print(volby[0], volby[1])
        #
        #     if volby[0] == 1:
        #         sys.stdout = outputFile
        #         casU1Zac = datetime.datetime.now()
        #         uloha1(rawPacketList)
        #         casU1Kon = datetime.datetime.now()
        #         sys.stdout = origVystup
        #         print("Funkcia uloha1() zabrala {} ms".format((casU1Kon - casU1Zac).total_seconds() * 1000))
        #
        #     # sys.stdout = outputFile
        #     # casU2Zac = datetime.datetime.now()
        #     # uloha2(rawPacketList, hexDict)
        #     # casU2Kon = datetime.datetime.now()
        #     # sys.stdout = origVystup
        #     # print("Funkcia uloha2() zabrala {} ms".format((casU2Kon - casU2Zac).total_seconds() * 1000))
        #
        #     if volby[0] == 3:
        #         sys.stdout = outputFile
        #         casU3Zac = datetime.datetime.now()
        #         uloha3(rawPacketList, hexDict)
        #         casU3Kon = datetime.datetime.now()
        #         sys.stdout = origVystup
        #         print("Funkcia uloha3() zabrala {} ms".format((casU3Kon - casU3Zac).total_seconds() * 1000))
        #
        #     if volby[0] >= 4 and volby[0] <= 12:
        #         sys.stdout = outputFile
        #         casU4Zac = datetime.datetime.now()
        #         uloha4(rawPacketList, hexDict, volby[1])
        #         casU4Kon = datetime.datetime.now()
        #         sys.stdout = origVystup
        #         print("Funkcia uloha4() zabrala {} ms".format((casU4Kon - casU4Zac).total_seconds() * 1000))
        #
        #     # print("packets {} {}".format(type(packets), sys.getsizeof(packets)))
        #     # print("packetList {} {}".format(type(packetList), sys.getsizeof(packetList)))
        #     # print("rawPacketList {} {}".format(type(rawPacketList), sys.getsizeof(rawPacketList)))
        #
        #     # print(filename)
        #
        #     outputFile.close()
        #
        #     volby = riadic()

        filename = cestakSuboru()
        # filename = None

    zaciatokFunkcie(main.__name__, False)

if __name__ == "__main__":
    main()
