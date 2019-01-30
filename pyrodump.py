import os
import time
import curses
import pcapy
import sys
from threading import Thread, Lock
from _datetime import datetime
from analysis import *

ap_list = []
st_list = []

hopping_ch = ["1", "7", "13", "2", "8", "14", "3", "9", "4", "10", "5", "11", "6", "12"]
num = 0


def hopping_channel(lock, interface):
    global hopping_ch
    global num

    while True:
        os.system("iwconfig %s channel %s" % (interface, hopping_ch[num]))
        lock.acquire()
        if num != 13:
            num = num + 1
        elif num == 13:
            num = 0
        lock.release()
        time.sleep(0.2)


def print_result(lock):
    global ap_list
    global st_list
    global hopping_ch
    global num

    start_time = datetime.now()
    scr = curses.initscr()

    while True:
        now_time = datetime.now()
        elapsed_time = int((now_time - start_time).total_seconds())

        scr.resize(200, 120)

        lock.acquire()
        if elapsed_time < 60:
            scr.addstr(0, 0, "CH %2s ][ Elapsed: %s s ][ %s-%s-%s %s:%s" % (
                hopping_ch[num], elapsed_time, now_time.year, now_time.month, now_time.day, now_time.hour,
                now_time.minute))

        elif 60 <= elapsed_time < 3600:
            scr.addstr(0, 0, "CH %2s ][ Elapsed: %s mins ][ %s-%s-%s %s:%s" % (
                hopping_ch[num], int(elapsed_time / 60), now_time.year, now_time.month, now_time.day, now_time.hour,
                now_time.minute))

        elif elapsed_time >= 3600:
            scr.addstr(0, 0, "CH %2s ][ Elapsed: %s hours ][ %s-%s-%s %s:%s" % (
                hopping_ch[num], int(elapsed_time / 3600), now_time.year, now_time.month, now_time.day, now_time.hour,
                now_time.minute))

        scr.addstr(2, 0, "BSSID              PWR  Beacons    #Data  CH  MB   ENC  CIPHER AUTH ESSID")

        if len(ap_list) < 30:
            for i in range(len(ap_list)):
                scr.addstr(4 + i, 0,
                           "%s" % ap_list[i][ApList.BSSID] + "%5s" % ap_list[i][ApList.PWR] + "%9s" % ap_list[i][ApList.BEACONS] +  # BSSID, PWR, Beacons
                           "%9s" % ap_list[i][ApList.DATA] + "%4s  " % ap_list[i][ApList.CH] + "%-5s" % ap_list[i][ApList.MB] +  # #Data, CH, MB
                           "%-5s" % ap_list[i][ApList.ENC] + "%-7s" % ap_list[i][ApList.CIPHER] + "%-5s" % ap_list[i][ApList.AUTH] +  # ENC, CIPHER, AUTH
                           "%s" % ap_list[i][ApList.ESSID])  # ESSID

            scr.addstr(5 + len(ap_list), 0, "BSSID              STATION            PWR   Rate    Lost    Frames  Probe")

            if len(st_list) != 0:
                for i in range(len(st_list)):
                    scr.addstr(7 + len(ap_list) + i, 0,
                               "%-19s" % st_list[i][StList.BSSID] + "%-19s" % st_list[i][StList.STAION] + "%-6s" % st_list[i][StList.PWR] +  # BSSID, STATION, PWR
                               "%3s-" % st_list[i][StList.AP_RATE] + "%-3s" % st_list[i][StList.ST_RATE] + "%6s" % st_list[i][StList.LOST] +  # APRate, STRate, Lost
                               "%9s" % st_list[i][StList.FRAMES] + "  %s" % st_list[i][StList.PROBE])  # Frames, Probe

        else:
            for i in range(30):
                scr.addstr(4 + i, 0,
                           "%s" % ap_list[i][ApList.BSSID] + "%5s" % ap_list[i][ApList.PWR] + "%9s" % ap_list[i][ApList.BEACONS] +  # BSSID, PWR, Beacons
                           "%9s" % ap_list[i][ApList.DATA] + "%4s  " % ap_list[i][ApList.CH] + "%-5s" % ap_list[i][ApList.MB] +  # #Data, CH, MB
                           "%-5s" % ap_list[i][ApList.ENC] + "%-7s" % ap_list[i][ApList.CIPHER] + "%-5s" % ap_list[i][ApList.AUTH] +  # ENC, CIPHER, AUTH
                           "%s" % ap_list[i][ApList.ESSID])  # ESSID

            scr.addstr(35, 0, "BSSID              STATION            PWR   Rate    Lost    Frames  Probe")

            if len(st_list) != 0:
                for i in range(len(st_list)):
                    scr.addstr(37 + i, 0,
                               "%-19s" % st_list[i][StList.BSSID] + "%-19s" % st_list[i][StList.STAION] + "%-6s" % st_list[i][StList.PWR] +  # BSSID, STATION, PWR
                               "%3s-" % st_list[i][StList.AP_RATE] + "%-3s" % st_list[i][StList.ST_RATE] + "%6s" % st_list[i][StList.LOST] +  # APRate, STRate, Lost
                               "%9s" % st_list[i][StList.FRAMES] + "  %s" % st_list[i][StList.PROBE])  # Frames, Probe

        lock.release()

        scr.refresh()
        time.sleep(0.1)
        scr.erase()


def get_ap_list(interface, lock):
    global ap_list
    global st_list

    while True:
        pcap = pcapy.open_live(interface, 512, 0, 0)  # get packet capture descriptor
        pkt = pcap.next()[1]

        dot11 = Dot11(pkt)

        lock.acquire()
        if dot11.type == Type.MANAGEMENT:
            if dot11.sub_type == MgtSubType.BEACON:

                # BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID
                ap = [dot11.addr3, dot11.pwr, 1, 0, dot11.channel, dot11.mb, dot11.enc, dot11.cipher, dot11.auth, dot11.ssid]

                if len(ap_list) != 0:
                    for i in range(len(ap_list)):

                        if ap_list[i][ApList.BSSID] == ap[ApList.BSSID]:
                            ap_list[i][ApList.PWR] = ap[ApList.PWR]
                            ap_list[i][ApList.BEACONS] += 1
                            ap_list[i][ApList.CH:] = ap[ApList.CH:]
                            break

                        elif i == len(ap_list) - 1:
                            ap_list.append(ap)

                else:
                    ap_list.append(ap)

            elif dot11.sub_type == dot11.sub_type == MgtSubType.PROBE_RESPONSE:
                # BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID
                ap = [dot11.addr3, dot11.pwr, 0, 0, 1, dot11.mb, dot11.enc, dot11.cipher, dot11.auth, dot11.ssid]

                if len(ap_list) != 0:
                    for i in range(len(ap_list)):

                        if ap_list[i][ApList.BSSID] == ap[ApList.BSSID]:
                            ap_list[i][ApList.PWR] = ap[ApList.PWR]
                            ap_list[i][ApList.MB:] = ap[ApList.MB:]
                            break

                        elif i == len(ap_list) - 1:
                            ap_list.append(ap)

                else:
                    ap_list.append(ap)

            elif dot11.sub_type == MgtSubType.PROBE_REQUEST:
                # BSSID, STAION, PWR, APRate, STRate, Lost, Frames, Probe, Seq
                st = ["(not associated)", dot11.addr2, dot11.pwr, "0", dot11.rate, 0, 1, dot11.ssid, dot11.seq]

                if len(st_list) != 0:
                    for i in range(len(st_list)):

                        if st_list[i][StList.STAION] == st[StList.STAION]:
                            st_list[i][StList.PWR] = st[StList.PWR]
                            st_list[i][StList.FRAMES] += 1
                            st_list[i][StList.PROBE] = st[StList.PROBE]

                            seq_diff = (st[StList.SEQ] - st_list[i][StList.SEQ]) - 1
                            st_list[i][StList.SEQ] = st[StList.SEQ]

                            if 0 < seq_diff < 1000:
                                st_list[i][StList.LOST] += seq_diff

                            break

                        elif i == len(st_list) - 1:
                            st_list.append(st)
                else:
                    st_list.append(st)

        elif dot11.type == Type.DATA and dot11.to_ds == 1 and dot11.from_ds == 0:
            # BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID
            if not dot11.is_no_data:
                ap = [dot11.addr1, -1, 0, 1, 1, -1, "", "", "", ""]
            else:
                ap = [dot11.addr1, -1, 0, 0, 1, -1, "", "", "", ""]

            if len(ap_list) != 0:
                for i in range(len(ap_list)):

                    if ap_list[i][ApList.BSSID] == ap[ApList.BSSID]:
                        ap_list[i][ApList.DATA] += ap[ApList.DATA]
                        break

                    elif i == len(ap_list) - 1:
                        ap_list.append(ap)

            else:
                ap_list.append(ap)

            # BSSID, STAION, PWR, APRate, STRate, Lost, Frames, Probe, Seq
            st = [dot11.addr1, dot11.addr2, dot11.pwr, "0", dot11.rate, 0, 1, "", dot11.seq]

            if len(st_list) != 0:
                for i in range(len(st_list)):

                    if st_list[i][StList.STAION] == st[StList.STAION]:
                        st_list[i][StList.BSSID] = st[StList.BSSID]
                        st_list[i][StList.PWR] = st[StList.PWR]
                        st_list[i][StList.ST_RATE] = st[StList.ST_RATE]
                        st_list[i][StList.FRAMES] += 1

                        seq_diff = (st[StList.SEQ] - st_list[i][StList.SEQ]) - 1
                        st_list[i][StList.SEQ] = st[StList.SEQ]

                        if 0 < seq_diff < 1000:
                            st_list[i][StList.LOST] += seq_diff


                        break

                    elif i == len(st_list) - 1:
                        st_list.append(st)

            else:
                st_list.append(st)

        elif dot11.type == Type.DATA and dot11.to_ds == 0 and dot11.from_ds == 1:
            # BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID
            if not dot11.is_no_data:
                ap = [dot11.addr2, dot11.pwr, 0, 1, 1, -1, "", "", "", ""]
            else:
                ap = [dot11.addr2, dot11.pwr, 0, 0, 1, -1, "", "", "", ""]

            if len(ap_list) != 0:
                for i in range(len(ap_list)):

                    if ap_list[i][ApList.BSSID] == ap[ApList.BSSID]:
                        ap_list[i][ApList.PWR] = ap[ApList.PWR]
                        ap_list[i][ApList.DATA] += ap[ApList.DATA]
                        break

                    elif i == len(ap_list) - 1:
                        ap_list.append(ap)

            else:
                ap_list.append(ap)

            # BSSID, STAION, PWR, APRate, STRate, Lost, Frames, Probe, Seq
            st = [dot11.addr2, dot11.addr1, -1, dot11.rate, "0", 0, 1, "", dot11.seq]

            if st[StList.STAION] != "FF:FF:FF:FF:FF:FF":
                if len(st_list) != 0:
                    for i in range(len(st_list)):

                        if st_list[i][StList.STAION] == st[StList.STAION]:
                            st_list[i][StList.BSSID] == st[StList.BSSID]
                            st_list[i][StList.AP_RATE] = st[StList.AP_RATE]

                            seq_diff = (st[StList.SEQ] - st_list[i][StList.SEQ]) - 1
                            st_list[i][StList.SEQ] = st[StList.SEQ]

                            if 0 < seq_diff < 1000:
                                st_list[i][StList.LOST] += seq_diff

                            break

                        elif i == len(st_list) - 1:
                            st_list.append(st)

                else:
                    st_list.append(st)

        ap_list.sort(key=lambda x: x[1], reverse=True)
        st_list.sort(reverse=True)
        lock.release()
                            

def main(interface):
    lock = Lock()

    t1 = Thread(target=hopping_channel, args=(lock, interface))
    t1.daemon = True
    t1.start()

    t2 = Thread(target=print_result, args=(lock,))
    t2.daemon = True
    t2.start()

    get_ap_list(interface, lock)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        main(sys.argv[1])
    else:
        print("syntax: python pyrodump.py <interface>")
