"""
해당 프로그램은 airodump와 유사한 기능을 구현하기 위해  Beacon Frame, Probe Request, 
Probe Response, Data Frame에 대한 정보를 이용하며 나머지 Frame에 대한 정보는 구하지 않는다.
"""


def get_channel(pkt, i, length):
    channel = pkt[i+1+length]

    return channel


def get_pwr(pkt, present_flag_list, base_length):
    pwr_location = base_length + present_flag_list[0] * 8 + present_flag_list[1] * 1 + present_flag_list[2] * 1 + \
                   present_flag_list[3] * 4 + present_flag_list[4] * 2
    pwr = pkt[pwr_location] - 256

    return pwr


def get_type(pkt, mac_header):
    type = (pkt[mac_header] & 0b00001100) >> 2

    return {0: "Management", 2: "Data"}.get(type, "Other")


def get_mgt_sub_type(pkt, radiotap_length):
    sub_type = (pkt[radiotap_length] & 0b11110000) >> 4

    return {4: "ProbeReq", 5: "ProbeResp", 8: "Beacon"}.get(sub_type, "Other")


def get_data_sub_type(pkt, radiotap_length):
    sub_type = (pkt[radiotap_length] & 0b11110000) >> 4

    return {0: "data", 1: "data + CF ACK", 2: "data + CF Poll", 3: "data + CF ACK + CF Poll",
            4: "Null", 5: "CF ACK", 6: "CF Poll", 7: "CF ACK + CF Poll",
            8: "QoS data", 9: "QoS data + CF Ack", 10: "QoS data + CF Poll", 11: "QoS data + CF Ack + CF Poll",
            12: "QoS Null", 14: "QoS CF Poll", 15: "QoS CF Ack + CF Pol"}.get(sub_type, "Other")


def get_to_ds(pkt, radiotap_length):
    to_ds = (pkt[radiotap_length+1] & 0b00000001)

    return to_ds


def get_from_ds(pkt, radiotap_length):
    from_ds = (pkt[radiotap_length + 1] & 0b00000010)

    return from_ds


def get_mgt_addr(pkt, radiotap_length):
    addr1 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 4])[2:].zfill(2),
        hex(pkt[radiotap_length + 5])[2:].zfill(2),
        hex(pkt[radiotap_length + 6])[2:].zfill(2),
        hex(pkt[radiotap_length + 7])[2:].zfill(2),
        hex(pkt[radiotap_length + 8])[2:].zfill(2),
        hex(pkt[radiotap_length + 9])[2:].zfill(2)
    )

    addr2 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 10])[2:].zfill(2),
        hex(pkt[radiotap_length + 11])[2:].zfill(2),
        hex(pkt[radiotap_length + 12])[2:].zfill(2),
        hex(pkt[radiotap_length + 13])[2:].zfill(2),
        hex(pkt[radiotap_length + 14])[2:].zfill(2),
        hex(pkt[radiotap_length + 15])[2:].zfill(2)
    )

    addr3 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 16])[2:].zfill(2),
        hex(pkt[radiotap_length + 17])[2:].zfill(2),
        hex(pkt[radiotap_length + 18])[2:].zfill(2),
        hex(pkt[radiotap_length + 19])[2:].zfill(2),
        hex(pkt[radiotap_length + 20])[2:].zfill(2),
        hex(pkt[radiotap_length + 21])[2:].zfill(2)
    )

    return addr1, addr2, addr3


def get_data_addr(pkt, radiotap_length):
    addr1 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 4])[2:].zfill(2),
        hex(pkt[radiotap_length + 5])[2:].zfill(2),
        hex(pkt[radiotap_length + 6])[2:].zfill(2),
        hex(pkt[radiotap_length + 7])[2:].zfill(2),
        hex(pkt[radiotap_length + 8])[2:].zfill(2),
        hex(pkt[radiotap_length + 9])[2:].zfill(2)
    )

    addr2 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 10])[2:].zfill(2),
        hex(pkt[radiotap_length + 11])[2:].zfill(2),
        hex(pkt[radiotap_length + 12])[2:].zfill(2),
        hex(pkt[radiotap_length + 13])[2:].zfill(2),
        hex(pkt[radiotap_length + 14])[2:].zfill(2),
        hex(pkt[radiotap_length + 15])[2:].zfill(2)
    )

    addr3 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 16])[2:].zfill(2),
        hex(pkt[radiotap_length + 17])[2:].zfill(2),
        hex(pkt[radiotap_length + 18])[2:].zfill(2),
        hex(pkt[radiotap_length + 19])[2:].zfill(2),
        hex(pkt[radiotap_length + 20])[2:].zfill(2),
        hex(pkt[radiotap_length + 21])[2:].zfill(2)
    )

    return addr1, addr2, addr3


def get_preamble(pkt, fixed_mac_body):
    if pkt[fixed_mac_body + 10] & 0b00100000:
        preamble = "."
    else:
        preamble = ""

    return preamble


def get_id(id):
    return {
        0: "SSID",
        1: "Rates",
        3: "DSSet",
        48: "RSN",
        50: "ERates",
        221: "Vender"
    }.get(id, "Other")


def get_cipher(cipher):
    return {
        0: "Use group cipher suite",
        1: "WEP-40",
        2: "TKIP",
        3: "Reserved",
        4: "CCMP",
        5: "WEP-104"
    }.get(cipher, "Other")


def get_auth(akm):
    return {
        0: "Reserved",
        1: "802.1X",
        2: "PSK"
    }.get(akm, "Other")


class Dot11:
    def __init__(self, pkt):
        # It is available variables
        self.channel = 1
        self.pwr = 0
        self.addr1 = ""
        self.addr2 = ""
        self.addr3 = ""
        self.addr4 = ""
        self.max_rate = 0
        self.qos = ""
        self.preamble = ""
        self.mb = ""
        self.enc = ""
        self.cipher = ""
        self.auth = ""
        self.is_qos_data = False
        self.ssid = ""

        # radiotap info
        self.radiotap_length = int.from_bytes(pkt[2:4], byteorder='little')
        self.present_flag = int.from_bytes(pkt[4:8], byteorder='little')
        self.present_flag_list = []

        for i in range(32):
            self.present_flag_list.append((self.present_flag & (2**i)) >> i)

        self.ext_flag = (pkt[7] & 0b10000000) >> 7
        self.ext_flag_count = 0

        while self.ext_flag == 1:
            self.ext_flag_count += 1
            self.ext_flag = (pkt[7+(4*self.ext_flag_count)] & 0b10000000) >> 7

        self.base_length = 8 + (4 * self.ext_flag_count)  # version, pad, len, present, 확장된 present 각각의 길이를 합한 길이

        self.pwr = get_pwr(pkt, self.present_flag_list, self.base_length)

        # mac info
        self.mac_header = self.radiotap_length
        self.type = get_type(pkt, self.mac_header)

        if self.type == "Management":
            self.sub_type = get_mgt_sub_type(pkt, self.radiotap_length)
            self.addr1, self.addr2, self.addr3 = get_mgt_addr(pkt, self.radiotap_length)

            self.fixed_mac_body = self.mac_header + 24
            self.variable_mac_body = self.fixed_mac_body + 12

            self.i = self.variable_mac_body

            if self.sub_type == "Beacon" or self.sub_type == "ProbeResp":
                self.preamble = get_preamble(pkt, self.fixed_mac_body)

                self.length = 0
                while self.i + 2 + self.length <= len(pkt):
                    self.id = get_id(pkt[self.i])
                    self.length = pkt[self.i + 1]
                    self.info = pkt[self.i + 2:self.i + 2 + self.length]

                    if self.id == "SSID":
                        try:
                            self.ssid = self.info.decode()
                        except:
                            pass

                    elif self.id == "Rates" or self.id == "ERates":
                        if self.max_rate < int(self.info[self.length - 1] / 2):
                            self.max_rate = int(self.info[self.length - 1] / 2)

                    elif self.id == "DSSet":
                        self.channel = get_channel(pkt, self.i, self.length)

                    elif self.id == "RSN":
                        self.enc = "WPA2"
                        self.cipher_count = int.from_bytes(pkt[self.i + 8:self.i + 10], byteorder='little')
                        self.oui = pkt[self.i + 10:self.i + 13]
                        if self.oui == b'\x00\x0f\xac':
                            self.cipher = get_cipher(pkt[self.i + 13])
                            self.auth = get_auth(pkt[self.i + 15 + (4 * self.cipher_count)])

                    elif self.id == "Vender" and pkt[self.i + 2:self.i + 8] == b'\x00\x50\xf2\x01\x01\x00':
                        self.enc = "WPA"
                        self.cipher_count = int.from_bytes(pkt[self.i + 12:self.i + 14], byteorder='little')
                        self.oui = pkt[self.i + 14:self.i + 17]
                        if self.oui == b'\x00\x50\xf2':
                            self.cipher = get_cipher(pkt[self.i + 17])
                            self.auth = get_auth(pkt[self.i + 19 + (4 * self.cipher_count)])

                    elif self.id == "Vender" and pkt[self.i + 2:self.i + 8] == b'\x00\x50\xf2\x02\x01\x01':
                        self.qos = "e"

                    self.i += 2 + self.length

                self.mb = str(self.max_rate) + self.qos + self.preamble

                if self.enc == "":
                    if ((pkt[self.fixed_mac_body + 11] & 0b00010000) >> 4) == 1:
                        self.enc = "WEP"
                        self.cipher = "WEP"
                    elif ((pkt[self.fixed_mac_body + 11] & 0b00010000) >> 4) == 0:
                        self.enc = "OPEN"

            elif self.sub_type == "ProbeReq":
                pass

        elif self.type == "Data":
            self.sub_type = get_data_sub_type(pkt, self.radiotap_length)
            self.to_ds = get_to_ds(pkt, self.radiotap_length)
            self.from_ds = get_from_ds(pkt, self.radiotap_length)
            self.addr1, self.addr2, self.addr3 = get_data_addr(pkt, self.radiotap_length)
