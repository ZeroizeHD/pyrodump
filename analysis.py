from data_def import *


def get_radiotap_field_location(present_flag_align_size, present_flag_list, radiotap_field_location, radiotap_fields):
    # for i in range(32):
    for i in range(6):
        if present_flag_list[i] == 0:
            pass

        elif present_flag_list[i] == 1 and radiotap_fields % present_flag_align_size[i][0] == 0:
            radiotap_field_location[i] = radiotap_fields
            radiotap_fields += present_flag_align_size[i][1]

        elif present_flag_list[i] == 1 and radiotap_fields % present_flag_align_size[i][0] != 0:
            radiotap_fields += present_flag_align_size[i][0] - (radiotap_fields % present_flag_align_size[i][0])
            radiotap_field_location[i] = radiotap_fields
            radiotap_fields += present_flag_align_size[i][1]

    return radiotap_field_location


def get_type(pkt, mac_header):
    type = (pkt[mac_header] & 0b00001100) >> 2

    return {0: Type.MANAGEMENT, 1: Type.CONTROL, 2: Type.DATA}.get(type, None)


def get_mgt_sub_type(pkt, radiotap_length):
    mgt_sub_type = (pkt[radiotap_length] & 0b11110000) >> 4

    return {0: MgtSubType.ASSOCIATION_REQUEST, 1: MgtSubType.ASSOCIATION_RESPONSE, 2: MgtSubType.REASSOCIATION_REQUEST,
            3: MgtSubType.ASSOCIATION_RESPONSE, 4: MgtSubType.PROBE_REQUEST, 5: MgtSubType.PROBE_RESPONSE,
            8: MgtSubType.BEACON, 9: MgtSubType.ATIM, 10: MgtSubType.DISASSOCIAITON,
            11: MgtSubType.AUTHENTICATION, 12: MgtSubType.DEAUTHENTICATION, 13: MgtSubType.ACTION,
            14: MgtSubType. ACTION_NO_ACK}.get(mgt_sub_type, None)


def get_data_sub_type(pkt, radiotap_length):
    data_sub_type = (pkt[radiotap_length] & 0b11110000) >> 4

    return {0: DataSubType.DATA, 1: DataSubType.DATA_CF_ACK, 2: DataSubType.DATA_CF_POLL,
            3: DataSubType.DATA_CF_ACK_CF_POLL, 4: DataSubType.NULL, 5: DataSubType.CF_ACK,
            6: DataSubType.CF_POLL, 7: DataSubType.CF_ACK_CF_POLL, 8: DataSubType.QOS_DATA,
            9: DataSubType.QOS_DATA_CF_ACK, 10: DataSubType.QOS_DATA_CF_POLL, 11: DataSubType.QOS_DATA_CF_ACK_CF_POLL,
            12: DataSubType.QOS_NULL, 13: DataSubType.RESERVED , 14: DataSubType.QOS_CF_POLL,
            15: DataSubType.QOS_CF_ACK_CF_POLL}.get(data_sub_type, None)


def get_to_ds(pkt, radiotap_length):
    to_ds = (pkt[radiotap_length+1] & 0b00000001)

    return to_ds


def get_from_ds(pkt, radiotap_length):
    from_ds = (pkt[radiotap_length + 1] & 0b00000010) >> 1

    return from_ds


def get_mgt_addr(pkt, radiotap_length):
    addr1 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 4])[2:].zfill(2), hex(pkt[radiotap_length + 5])[2:].zfill(2), hex(pkt[radiotap_length + 6])[2:].zfill(2),
        hex(pkt[radiotap_length + 7])[2:].zfill(2), hex(pkt[radiotap_length + 8])[2:].zfill(2), hex(pkt[radiotap_length + 9])[2:].zfill(2))

    addr2 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 10])[2:].zfill(2), hex(pkt[radiotap_length + 11])[2:].zfill(2), hex(pkt[radiotap_length + 12])[2:].zfill(2),
        hex(pkt[radiotap_length + 13])[2:].zfill(2), hex(pkt[radiotap_length + 14])[2:].zfill(2), hex(pkt[radiotap_length + 15])[2:].zfill(2))

    addr3 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 16])[2:].zfill(2), hex(pkt[radiotap_length + 17])[2:].zfill(2), hex(pkt[radiotap_length + 18])[2:].zfill(2),
        hex(pkt[radiotap_length + 19])[2:].zfill(2), hex(pkt[radiotap_length + 20])[2:].zfill(2), hex(pkt[radiotap_length + 21])[2:].zfill(2))

    return addr1.upper(), addr2.upper(), addr3.upper()


def get_data_addr(pkt, radiotap_length):
    addr1 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 4])[2:].zfill(2), hex(pkt[radiotap_length + 5])[2:].zfill(2), hex(pkt[radiotap_length + 6])[2:].zfill(2),
        hex(pkt[radiotap_length + 7])[2:].zfill(2), hex(pkt[radiotap_length + 8])[2:].zfill(2), hex(pkt[radiotap_length + 9])[2:].zfill(2))

    addr2 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 10])[2:].zfill(2), hex(pkt[radiotap_length + 11])[2:].zfill(2), hex(pkt[radiotap_length + 12])[2:].zfill(2),
        hex(pkt[radiotap_length + 13])[2:].zfill(2), hex(pkt[radiotap_length + 14])[2:].zfill(2), hex(pkt[radiotap_length + 15])[2:].zfill(2))

    addr3 = "%s:%s:%s:%s:%s:%s" % (
        hex(pkt[radiotap_length + 16])[2:].zfill(2), hex(pkt[radiotap_length + 17])[2:].zfill(2), hex(pkt[radiotap_length + 18])[2:].zfill(2),
        hex(pkt[radiotap_length + 19])[2:].zfill(2), hex(pkt[radiotap_length + 20])[2:].zfill(2), hex(pkt[radiotap_length + 21])[2:].zfill(2))

    return addr1.upper(), addr2.upper(), addr3.upper()


def get_preamble(pkt, fixed_mac_body):
    if pkt[fixed_mac_body + 10] & 0b00100000:
        preamble = "."
    else:
        preamble = ""

    return preamble


def get_id(id):
    return {
        0: ID.SSID,
        1: ID.RATES,
        3: ID.DSSET,
        48: ID.RSN,
        50: ID.ERATES,
        221: ID.VENDER
    }.get(id, None)


def get_channel(pkt, i, length):
    channel = pkt[i+1+length]

    return channel


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


def is_no_data(sub_type):
    return {DataSubType.NULL: 1, DataSubType.CF_ACK: 1, DataSubType.CF_POLL: 1, DataSubType.CF_ACK_CF_POLL: 1,
            DataSubType.QOS_NULL: 1, DataSubType.QOS_CF_POLL: 1, DataSubType.QOS_CF_ACK_CF_POLL: 1}.get(sub_type, 0)


class Dot11:
    def __init__(self, pkt):
        # It is available variables
        # radiotab
        self.rate = "1"
        self.pwr = -1

        # mac header
        self.type = None
        self.sub_type = None
        self.to_ds = 0
        self.from_ds = 0
        self.addr1 = ""
        self.addr2 = ""
        self.addr3 = ""
        self.seq = 0

        # mac body
        self.preamble = ""
        self.ssid = ""
        self.max_rate = -1
        self.channel = 1
        self.mb = ""
        self.enc = ""
        self.cipher = ""
        self.auth = ""
        self.qos = ""

        # etc
        self.is_no_data = 0

        # radiotap info
        self.radiotap_length = int.from_bytes(pkt[2:4], byteorder='little')
        self.present_flag = int.from_bytes(pkt[4:8], byteorder='little')

        self.present_flag_align_size = [[8, 8], [1, 1], [1, 1], [2, 4], [2, 2], [1, 1], [0, 0], [0, 0],
                                        [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0],
                                        [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0],
                                        [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]

        self.present_flag_list = [0 for _ in range(32)]

        for i in range(32):
            self.present_flag_list[i] = (self.present_flag & (2 ** i)) >> i

        self.radiotap_field_location = [0 for _ in range(32)]

        self.ext_flag = (pkt[7] & 0b10000000) >> 7
        self.ext_flag_count = 0

        while self.ext_flag == 1:
            self.ext_flag_count += 1
            self.ext_flag = (pkt[7+(4*self.ext_flag_count)] & 0b10000000) >> 7

        self.radiotap_fields = 8 + (4 * self.ext_flag_count)  # Sum length of version, pad, len, present, extended present

        self.radiotap_field_location = get_radiotap_field_location\
            (self.present_flag_align_size, self.present_flag_list, self.radiotap_field_location, self.radiotap_fields)

        self.pwr = pkt[self.radiotap_field_location[PRESENT_FLAG.ANTENNA_SIGNAL]] - 256
        self.rate = str(int(pkt[self.radiotap_field_location[PRESENT_FLAG.RATE]] * 0.5))

        # mac info
        self.mac_header = self.radiotap_length
        self.type = get_type(pkt, self.mac_header)

        # Management Frame, Data Frame have sequence control field
        self.seq = int.from_bytes(pkt[self.mac_header+22:self.mac_header+24], byteorder='little')
        self.seq = (self.seq & 0b1111111111110000) >> 4

        if self.type == Type.MANAGEMENT:
            self.sub_type = get_mgt_sub_type(pkt, self.radiotap_length)

            self.addr1, self.addr2, self.addr3 = get_mgt_addr(pkt, self.radiotap_length)

            if self.sub_type == MgtSubType.BEACON or self.sub_type == MgtSubType.PROBE_RESPONSE:
                self.fixed_mac_body = self.mac_header + 24
                self.preamble = get_preamble(pkt, self.fixed_mac_body)

                self.variable_mac_body = self.fixed_mac_body + 12
                self.i = self.variable_mac_body

                self.length = 0
                while self.i + 2 + self.length <= len(pkt):
                    self.id = get_id(pkt[self.i])
                    self.length = pkt[self.i + 1]
                    self.info = pkt[self.i + 2:self.i + 2 + self.length]

                    if self.id == ID.SSID:
                        try:
                            self.ssid = self.info.decode()
                        except UnicodeDecodeError:
                            pass

                    elif self.id == ID.RATES or self.id == ID.ERATES:
                        if self.max_rate < int(self.info[self.length - 1] / 2):
                            self.max_rate = int(self.info[self.length - 1] / 2)

                    elif self.id == ID.DSSET:
                        self.channel = get_channel(pkt, self.i, self.length)

                    elif self.id == ID.RSN:
                        self.enc = "WPA2"
                        self.cipher_count = int.from_bytes(pkt[self.i + 8:self.i + 10], byteorder='little')
                        self.oui = pkt[self.i + 10:self.i + 13]
                        if self.oui == b'\x00\x0f\xac':
                            self.cipher = get_cipher(pkt[self.i + 13])
                            self.auth = get_auth(pkt[self.i + 15 + (4 * self.cipher_count)])

                    elif self.id == ID.VENDER and pkt[self.i + 2:self.i + 8] == b'\x00\x50\xf2\x01\x01\x00':
                        self.enc = "WPA"
                        self.cipher_count = int.from_bytes(pkt[self.i + 12:self.i + 14], byteorder='little')
                        self.oui = pkt[self.i + 14:self.i + 17]
                        if self.oui == b'\x00\x50\xf2':
                            self.cipher = get_cipher(pkt[self.i + 17])
                            self.auth = get_auth(pkt[self.i + 19 + (4 * self.cipher_count)])

                    elif self.id == ID.VENDER and pkt[self.i + 2:self.i + 8] == b'\x00\x50\xf2\x02\x01\x01':
                        self.qos = "e"

                    self.i += 2 + self.length

                self.mb = str(self.max_rate) + self.qos + self.preamble

                if self.enc == "":
                    if ((pkt[self.fixed_mac_body + 11] & 0b00010000) >> 4) == 1:
                        self.enc = "WEP"
                        self.cipher = "WEP"
                    elif ((pkt[self.fixed_mac_body + 11] & 0b00010000) >> 4) == 0:
                        self.enc = "OPEN"

            elif self.sub_type == MgtSubType.PROBE_REQUEST:
                self.variable_mac_body = self.mac_header + 24

                self.id = get_id(pkt[self.variable_mac_body])
                self.length = pkt[self.variable_mac_body + 1]
                self.info = pkt[self.variable_mac_body + 2:self.variable_mac_body + 2 + self.length]

                if self.id == ID.SSID:
                    try:
                        self.ssid = self.info.decode()
                    except UnicodeDecodeError:
                        pass

        elif self.type == Type.DATA:
            self.sub_type = get_data_sub_type(pkt, self.radiotap_length)
            self.is_no_data = is_no_data(self.sub_type)
            self.is_qos_data = (pkt[self.radiotap_length] & 0b10000000) >> 7

            if self.is_qos_data == 1:
                self.rate += "e"

            self.to_ds = get_to_ds(pkt, self.radiotap_length)
            self.from_ds = get_from_ds(pkt, self.radiotap_length)

            self.addr1, self.addr2, self.addr3 = get_data_addr(pkt, self.radiotap_length)
