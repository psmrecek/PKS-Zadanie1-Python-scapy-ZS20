from scapy.all import *
import os
import struct
import sys
import datetime

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

def cesta(relCesta=""):
    zaciatokFunkcie(cesta.__name__, True)

    dirname = os.path.dirname(__file__)

    return(os.path.join(dirname, relCesta))
    # return dirname + "/" + relCesta

    zaciatokFunkcie(cesta.__name__, False)

def cestakSuboru():
    zaciatokFunkcie(cestakSuboru.__name__, True)

    path = cesta("zoznamSuborov.txt")
    # print(path)

    s = open(path, "r")
    zoznam = s.readlines()
    s.close()

    for number, line in enumerate(zoznam, 1):
        print("{:03}: {}".format(number, line), end="")

    print("Stlac -1 pre ukoncenie programu, 0 pre zadanie vlastnej cesty alebo vyber cislo suboru od 1 do ",
          len(zoznam))

    while True:
        vyber = int(input())

        if (vyber == -1):
            print("Koniec programu")
            return
        elif (vyber == 0):
            print("Zadaj vlastnu relativnu cestu k suboru:")
            vlastnaCesta = input()
            return cesta(vlastnaCesta)
        elif (vyber > 0 and vyber <= len(zoznam)):
            return cesta((zoznam[vyber - 1])[:-1])

        print("Nespravna volba, zadaj znova:")

    zaciatokFunkcie(cestakSuboru.__name__, False)

def uloha1(rawPacketList):
    zaciatokFunkcie(uloha1.__name__, True)

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
        print("")

    zaciatokFunkcie(uloha1.__name__, False)

def main():
    zaciatokFunkcie(main.__name__, True)

    origVystup = sys.stdout

    filename = cestakSuboru()

    while filename != None:
        outputFile = open(cesta('vystup.txt'), 'w')
        sys.stdout = origVystup

        print("Bola zvolena cesta ", filename)

        casCitanieZac = datetime.datetime.now()

        packets = rdpcap(filename)
        casCitanieKon = datetime.datetime.now()

        print("Citanie suboru zabralo {} ms".format((casCitanieKon - casCitanieZac).total_seconds() * 1000))

        casPrepisuZac = datetime.datetime.now()
        rawPacketList = [raw(p) for p in packets]
        casPrepisuKon = datetime.datetime.now()

        print("Prepis suboru zabral {} ms".format((casPrepisuKon - casPrepisuZac).total_seconds() * 1000))

        sys.stdout = outputFile
        casU1Zac = datetime.datetime.now()
        uloha1(rawPacketList)
        casU1Kon = datetime.datetime.now()
        sys.stdout = origVystup

        print("Funkcia uloha1() zabrala {} ms".format((casU1Kon - casU1Zac).total_seconds() * 1000))

        outputFile.close()
        filename = cestakSuboru()
        # filename = None



    zaciatokFunkcie(main.__name__, False)


if __name__ == "__main__":
    main()







