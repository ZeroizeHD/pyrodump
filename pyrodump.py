import os
import time
import curses
import analysis
import pcapy
from threading import Thread, Lock
from _datetime import datetime

ap_list = []
st_list = []

hopping_ch = ["1", "7", "13", "2", "8", "14", "3", "9", "4", "10", "5", "11", "6", "12"]
num = 0


def hopping_channel():
    global hopping_ch
    global num

    lock = Lock()
    while True:
        os.system("iwconfig mon0 channel %s" % hopping_ch[num])
        lock.acquire()
        if num != 13:
            num = num + 1
        elif num == 13:
            num = 0
        lock.release()
        time.sleep(0.3)


def get_ap_list(pkt):
    ap = []

    dot11 = analysis.Dot11(pkt)

    if dot11.type == "Management":
        if dot11.sub_type == "Beacon" or dot11.sub_type == "ProbeResp":
            ap.append(dot11.addr3)  # BSSID
            ap.append(dot11.pwr)  # PWR
            ap.append(1)  # Beacons
            ap.append(0)  # #Data
            ap.append(0)  # #/s, Number of data packets per second measure over the last 10 seconds.
            ap.append(dot11.channel)  # CH
            ap.append(dot11.mb)  # MB
            ap.append(dot11.enc)  # ENC
            ap.append(dot11.cipher)  # CIPHER
            ap.append(dot11.auth)  # AUTH
            ap.append(dot11.ssid)  # ESSID

            if len(ap_list) != 0:
                for i in range(len(ap_list)):
                    if ap_list[i][0] == ap[0]:
                        if dot11.sub_type == "Beacon":
                            ap_list[i][2] = ap_list[i][2] + 1
                            break
                        else:
                            break

                    elif i == len(ap_list) - 1:
                        ap_list.append(ap)
            else:
                ap_list.append(ap)

            ap_list.sort(key=lambda x: x[1], reverse=True)

        elif dot11.sub_type == "ProbeReq":
            pass
    elif dot11.type == "Data":
        if len(ap_list):
            if dot11.from_ds is False or dot11.from_ds is False:
                for x in range(len(ap_list)):
                    if ap_list[x][0] == dot11.addr1 or ap_list[x][0] == dot11.addr2 or ap_list[x][0] == dot11.addr3:
                        ap_list[x][3] += 1
                        break
            else:
                for x in range(len(ap_list)):
                    if ap_list[x][0] == dot11.addr1 or ap_list[x][0] == dot11.addr2 or ap_list[x][0] == dot11.addr3 or ap_list[x][0] == dot11.addr4:
                        ap_list[x][3] += 1
                        break


start_time = datetime.now()
elapsed_time = 0

t = Thread(target=hopping_channel)
t.start()

scr = curses.initscr()

while True:
    scr.resize(200, 120)

    pcap = pcapy.open_live("mon0", 1000, 0, 0)  # get packet capture descriptor
    pkt = pcap.next()[1]

    get_ap_list(pkt)

    now_time = datetime.now()
    elapsed_time = int((now_time - start_time).total_seconds())

    if elapsed_time < 60:
        scr.addstr(0, 0, "CH  %s ][ Elapsed: %s s ][ %s-%s-%s %s:%s" % (
            hopping_ch[num], elapsed_time, now_time.year, now_time.month, now_time.day, now_time.hour, now_time.minute))

    elif 60 <= elapsed_time < 3600:
        scr.addstr(0, 0, "CH  %s ][ Elapsed: %s mins ][ %s-%s-%s %s:%s" % (
            hopping_ch[num], int(elapsed_time / 60), now_time.year, now_time.month, now_time.day, now_time.hour, now_time.minute))

    elif elapsed_time >= 3600:
        scr.addstr(0, 0, "CH  %s ][ Elapsed: %s hours ][ %s-%s-%s %s:%s" % (
            hopping_ch[num], int(elapsed_time / 3600), now_time.year, now_time.month, now_time.day, now_time.hour, now_time.minute))

    scr.addstr(2, 0, "BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID")

    if len(ap_list) != 0:
        for i in range(len(ap_list)):
            scr.addstr(4 + i, 0,
                       "%s" % ap_list[i][0] + "%5s" % ap_list[i][1] + "%9s" % ap_list[i][2] +  # BSSID, PWR, Beacons
                       "%9s" % ap_list[i][3] + "%5s" % ap_list[i][4] + "%4s  " % ap_list[i][5] +  # #Data, #/s, CH
                       "%-5s" % ap_list[i][6] + "%-5s" % ap_list[i][7] + "%-7s" % ap_list[i][8] +  # MB, ENC, CIPHER
                       "%-5s" % ap_list[i][9] + "%s" % ap_list[i][10])  # AUTH, ESSID

    scr.addstr(5 + len(ap_list), 0, "BSSID              STATION            PWR   Rate    Lost    Frames  Probe")

    scr.refresh()
    scr.erase()
