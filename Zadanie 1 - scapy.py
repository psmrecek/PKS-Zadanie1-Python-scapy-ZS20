from scapy.all import *
import os
import struct
import sys

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

def uloha1(rawPacketList):
    zaciatokFunkcie(uloha1.__name__, True)

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

        print("Typ rámca:", end=" ")
        if item[12:13] < b'\x06':
            # print("{} {}".format(item[12:13], b'\x06'))
            if item[14:15] == b'\xFF':
                print("Novell 802.3 RAW")
            elif item[14:15] == b'\xAA':
                print("IEEE 802.3 LLC + SNAP")
            else:
                print("IEEE 802.3 LLC")
        else:
            print("Ethernet II")


        print("Zdrojová MAC adresa:", end=" ")
        for a in item[6:12]:
            print("{:02x}".format(a), end=" ")

        print("\nCieľová MAC adresa:", end=" ")
        for a in item[0:6]:
            print("{:02x}".format(a), end=" ")
        print()


        # vlastnyHexdump(item)
        # print("\n")
        hexdump(item)

        print("\n")

    zaciatokFunkcie(uloha1.__name__, False)

def cesta(relCesta = ""):
    zaciatokFunkcie(cesta.__name__, True)

    dirname = os.path.dirname(__file__)
    # filename = os.path.join(dirname, 'vzorky_pcap_na_analyzu/eth-8.pcap')
    #filename = os.path.join(dirname, 'vzorky_pcap_na_analyzu/trace-24.pcap')
    #print(dirname)
    #print(type(dirname))
    #return(os.path.join(dirname, relCesta))
    return dirname + "/" + relCesta
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

        # vyber = 26

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

def main():
    zaciatokFunkcie(main.__name__, True)

    filename = cestakSuboru()

    while filename != None:
        print("Bola zvolena cesta ", filename)

        packets = rdpcap(filename)                  # musim pouzit raw
        # packets = RawPcapReader(filename)           # vracia tuple
        # packets2 = PcapReader(filename)              # vracia to iste ako rdpcap a tiez treba pouzit raw
        # packets = sniff(filename)                   # nefunguje

        packetList = PacketList([p for p in packets])
        rawPacketList = [raw(p) for p in packetList]
        uloha1(rawPacketList)

        # print("packets {} {}".format(type(packets), sys.getsizeof(packets)))
        # print("packetList {} {}".format(type(packetList), sys.getsizeof(packetList)))
        # print("rawPacketList {} {}".format(type(rawPacketList), sys.getsizeof(rawPacketList)))

        # print(filename)

        # filename = cestakSuboru()
        filename = None

    zaciatokFunkcie(main.__name__, False)

if __name__ == "__main__":
    main()




 


