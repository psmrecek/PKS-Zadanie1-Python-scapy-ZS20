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
        # vyber = int(input())
        vyber = 3               # kratky vzorovy vstup
        # vyber = 25              # najvacsi vzorovy vstup
        # vyber = 30              # obsahuje RAW
        # vyber = 36              # obsahuje SNAP

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
            # print(meno, int(cislo, 16))

            hexDict[meno, int(cislo, 16)] = nazov[:-1]
    return hexDict

def uloha1(rawPacketList):
    zaciatokFunkcie(uloha1.__name__, True)

    # sumRamcov = 0

    ramec = 1
    for item in rawPacketList:
        print("rámec", ramec)
        ramec += 1

        # print(type(item))
        # print(item)

        # break

        dlzkaAPI = len(item)
        dlzkaMedium = dlzkaAPI + 4
        if dlzkaMedium < 64:
            dlzkaMedium = 64

        print("Dĺžka rámca poskytnutá pcap API – {} B".format(dlzkaAPI))
        print("Dĺžka rámca prenášaného po médiu – {} B".format(dlzkaMedium))

        # print("Velkost ramca na disku je ", sys.getsizeof(item))
        # sumRamcov += sys.getsizeof(item)

        # print("Typ rámca:", end=" ")
        # if item[12:13] < b'\x06':
        #     # print("{} {}".format(item[12:13], b'\x06'))
        #     if item[14:15] == b'\xFF':
        #         print("Novell 802.3 RAW")
        #     elif item[14:15] == b'\xAA':
        #         print("IEEE 802.3 LLC + SNAP")
        #     else:
        #         print("IEEE 802.3 LLC")
        # else:
        #     print("Ethernet II")

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
        print("")

    # print("Cely subor ma {} b".format(sumRamcov))

    zaciatokFunkcie(uloha1.__name__, False)

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
            if num1213 == 0x0800:
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

        print("Zdrojová MAC adresa:", " ".join("{:02X}".format(x) for x in item[6:12]))
        print("Cieľová MAC adresa:", " ".join("{:02X}".format(x) for x in item[0:6]))


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

def main():
    zaciatokFunkcie(main.__name__, True)

    origVystup = sys.stdout

    filename = cestakSuboru()

    while filename != None:
        outputFile = open(cesta('vystup.txt'), 'w')
        sys.stdout = origVystup

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

        # sys.stdout = outputFile
        # casU1Zac = datetime.datetime.now()
        # uloha1(rawPacketList)
        # casU1Kon = datetime.datetime.now()
        # sys.stdout = origVystup
        # print("Funkcia uloha1() zabrala {} ms".format((casU1Kon - casU1Zac).total_seconds() * 1000))

        # sys.stdout = outputFile
        # casU2Zac = datetime.datetime.now()
        # uloha2(rawPacketList, hexDict)
        # casU2Kon = datetime.datetime.now()
        # sys.stdout = origVystup
        # print("Funkcia uloha2() zabrala {} ms".format((casU2Kon - casU2Zac).total_seconds() * 1000))

        # sys.stdout = outputFile
        casU3Zac = datetime.datetime.now()
        uloha3(rawPacketList, hexDict)
        casU3Kon = datetime.datetime.now()
        # sys.stdout = origVystup
        print("Funkcia uloha3() zabrala {} ms".format((casU3Kon - casU3Zac).total_seconds() * 1000))

        # print("packets {} {}".format(type(packets), sys.getsizeof(packets)))
        # print("packetList {} {}".format(type(packetList), sys.getsizeof(packetList)))
        # print("rawPacketList {} {}".format(type(rawPacketList), sys.getsizeof(rawPacketList)))

        # print(filename)

        outputFile.close()
        # filename = cestakSuboru()
        filename = None

    zaciatokFunkcie(main.__name__, False)

if __name__ == "__main__":
    main()







