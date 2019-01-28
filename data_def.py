from enum import *


class PRESENT_FLAG(IntEnum):
    TSTF = 0
    FLAGS = 1
    RATE = 2
    CHANNEL = 3
    FHSS = 4
    ANTENNA_SIGNAL = 5


class Type(IntEnum):
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2


class MgtSubType(IntEnum):
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    PROBE_REQUEST = 4
    PROBE_RESPONSE = 5
    BEACON = 8
    ATIM = 9
    DISASSOCIAITON = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13
    ACTION_NO_ACK = 14


class DataSubType(IntEnum):
    DATA = 0
    DATA_CF_ACK = 1
    DATA_CF_POLL = 2
    DATA_CF_ACK_CF_POLL = 3
    NULL = 4
    CF_ACK = 5
    CF_POLL = 6
    CF_ACK_CF_POLL = 7
    QOS_DATA = 8
    QOS_DATA_CF_ACK = 9
    QOS_DATA_CF_POLL = 10
    QOS_DATA_CF_ACK_CF_POLL = 11
    QOS_NULL = 12
    RESERVED = 13
    QOS_CF_POLL = 14
    QOS_CF_ACK_CF_POLL = 15


class ID(IntEnum):
    SSID = 0
    RATES = 1
    DSSET = 3
    RSN = 48
    ERATES = 50
    VENDER = 221


class ApList(IntEnum):
    BSSID = 0
    PWR = 1
    BEACONS = 2
    DATA = 3
    CH = 4
    MB = 5
    ENC = 6
    CIPHER = 7
    AUTH = 8
    ESSID = 9


class StList(IntEnum):
    BSSID = 0
    STAION = 1
    PWR = 2
    AP_RATE = 3
    ST_RATE = 4
    LOST = 5
    FRAMES = 6
    PROBE = 7
    SEQ = 8
