from scapy.all import *
import os

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


def uloha1(packetList, filename):
    zaciatokFunkcie(uloha1.__name__, True)

    ramec = 1
    for item in packetList:
        print("rámec", ramec)
        ramec += 1

        b = raw(item)
        n = 0
        print("dĺžka rámca poskytnutá pcap API – {} B".format(len(b)))
        print("dĺžka rámca prenášaného po médiu – {} B".format("neviem"))
        print("typ")
        print("Zdrojová MAC adresa:", end=" ")
        for a in b[6:12]:
            print("{:02x}".format(a), end=" ")
    #    print("\n")
        print("\nCieľová MAC adresa:", end=" ")
        for a in b[0:6]:
            print("{:02x}".format(a), end=" ")
        print("\nneviem")
        print("zdrojová IP adresa: ", end=" ")
        print()
        print("cieľová IP adresa: ", end=" ")
        print()

        for a in b:
            n += 1
            if n % 16 == 0:
                print("{:02x}".format(a))
            elif n % 8 == 0:
                print("{:02x}".format(a), end="  ")
            else:
                print("{:02x}".format(a), end=" ")
        n = 0
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

#    filename = cesta('vzorky_pcap_na_analyzu/eth-8.pcap')

    filename = cestakSuboru()

    while filename != None:
        print("Bola zvolena cesta ", filename)
        packets = rdpcap(filename)

        packetList = PacketList([p for p in packets])
        #print(filename)

        #cestakSuboru()
        uloha1(packetList, filename)

        filename = cestakSuboru()


    # b = raw(packetList[0])
    # print({":02x"}.format(b[22]))

    # for packet in packetList:
    #     print(packet, "\n\n\n")
    #    print (''.join("{:02x}".format(ord(str(x))) for x in packet))
    #    print(packet)

    zaciatokFunkcie(main.__name__, False)

if __name__ == "__main__":
    main()




 


