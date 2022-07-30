import pexpect
import sys
import getopt
import logging
import time

test_data = [
    ['4500', '00d0', '0190', '0000', 'ff06', 'bf03', 'c0a8', '01cc'], # 0
    ['2f58', '08c8', '0919', '2710', '0000', '3666', 'a879', 'fda3'], # 16
    ['5018', '0b8a', '4bf4', '0000', 'a59b', '0010', '4206', '7f8b'], # 32
    ['2a6a', '8901', '0127', 'c829', '0200', 'dd29', '0000', '42b6'], # 48
    ['e262', '0100', '2702', '0000', '5346', '3445', '5330', '3034'], # 64
    ['4d41', '4a38', '3433', '2020', '5e01', '880b', 'e702', '0900'], # 80
    ['0000', '0900', '0900', '0900', '1409', '0f09', '0f09', '8813'], # 96
    ['dc00', '0000', '4200', '0000', 'a000', '0000', '2700', '0000'], # 112
    ['0200', '0000', '0000', '0000', '0000', '0000', '0000', '0000'], # 128
    ['4733', '3330', '5631', '3030', '1200', 'b218', '880b', 'fa02'], # 144
    ['3c00', '0100', '6705', '8906', '3f05', '1600', '0000', '0000'], # 160
    ['0500', 'e303', 'e303', 'e403', '5633', '3330', '5633', '3330'], # 176
    ['1607', '1e0a', '2537', '1a00', '0000', '49fa', '0000', '6f15'], # 192
]

def sofar_sniffer(ip, iface, log_file=None, cap_file=None, dump_cmd=None):
    inverter_data = []

    if dump_cmd:
        cmd = dump_cmd
    else:
        if cap_file:
            cmd = "tcpdump -i {} -U --print -w {} -x tcp and src {}".format(iface, cap_file, ip)
        else:
            cmd = "tcpdump -i {} -x tcp and src {}".format(iface, ip)

    logging.info("command: {}".format(cmd))
    p = pexpect.spawnu(cmd, timeout=None)

    while True:
        l = p.readline().strip()
        if l[0:2] == "0x":
            offset = int(l[2:6], 16)
            v = l[7:].split(" ")
            v = list(filter(None, v))

            if offset == 0:
                logging.debug("packet start")
                inverter_data = []

            inverter_data.append(v)

            if offset == 192:
                logging.debug("parse inverter data")
                sofar_parse(inverter_data, log_file)

def sofar_parse_short(hex_str):
    v = int(hex_str, 16)
    v = (v << 8) | (v >> 8)
    return v & 0xffff

def sofar_get_hex(inverter_data, offset):
    row = offset // 16
    col = (offset % 16) // 2
    return inverter_data[row][col]

def sofar_parse(inverter_data, log_file=None):
    # TODO add some checks for packet validity

    i_production = sofar_parse_short(sofar_get_hex(inverter_data, 116)) / 100
    i_power = sofar_parse_short(sofar_get_hex(inverter_data, 112))
    i_temp = sofar_parse_short(sofar_get_hex(inverter_data, 88)) / 10
    i_u1 = sofar_parse_short(sofar_get_hex(inverter_data, 104)) / 10
    i_u2 = sofar_parse_short(sofar_get_hex(inverter_data, 106)) / 10
    i_u3 = sofar_parse_short(sofar_get_hex(inverter_data, 108)) / 10
    i_i1 = sofar_parse_short(sofar_get_hex(inverter_data, 98)) / 10
    i_i2 = sofar_parse_short(sofar_get_hex(inverter_data, 100)) / 10
    i_i3 = sofar_parse_short(sofar_get_hex(inverter_data, 102)) / 10
    i_freq = sofar_parse_short(sofar_get_hex(inverter_data, 110)) / 100
    i_udc = sofar_parse_short(sofar_get_hex(inverter_data, 90)) / 10
    i_idc = sofar_parse_short(sofar_get_hex(inverter_data, 94)) / 10
    i_time = int(time.time())

    logging.info("  production: {} kWh".format(i_production))
    logging.info("  power     : {} W".format(i_power))
    logging.info("  temp      : {} C".format(i_temp))
    logging.info("  DC U, I   : {} V, {} A".format(i_udc, i_idc))
    logging.info("  L1 U, I   : {} V, {} A".format(i_u1, i_i1))
    logging.info("  L2 U, I   : {} V, {} A".format(i_u2, i_i2))
    logging.info("  L3 U, I   : {} V, {} A".format(i_u3, i_i3))
    logging.info("  frequency : {} Hz".format(i_freq))
    logging.info("")

    if log_file:
        csv = ("{}," * 12 + "{}\n").format(i_time, i_production, i_power, i_temp, i_udc, i_idc, i_u1, i_u2, i_u3, i_i1, i_i2, i_i3, i_freq)
        log_file.write(csv)
        log_file.flush()

def sofar_usage():
    print("Sofar solar inverter logger sniffer tool")
    print(" -a <ip> inverter IP address")
    print(" -i <iface> inverter interface name (default wlan0)")
    print(" -w <file> output CSV file name")
    print(" -d <file> tcpdump capture file name")
    print(" -c <command> packet logger system command")
    print(" -v <DEBUG | INFO | ERROR> set debug level")
    print(" -h show this usage")

if __name__ == "__main__":
    opt_ip = "192.168.1.204"
    opt_if = "wlan0"
    opt_log = None
    opt_cap = None
    opt_cmd = None
    opt_dbg = "INFO"

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:i:w:d:c:v:")
    except getopt.GetoptError as err:
        print(err)
        sofar_usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-h":
            sofar_usage()
            sys.exit(0)
        elif o == "-a":
            opt_ip = a
        elif o == "-i":
            opt_if = a
        elif o == "-w":
            opt_log = open(a, "a")
        elif o == "-d":
            opt_cap = a
        elif o == "-c":
            opt_cmd = a
        elif o == "-v":
            opt_dbg = a
        else:
            assert False, "Unhandled option"

    logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%d.%m.%Y %H:%M:%S", level=getattr(logging, opt_dbg.upper()))
    logging.info("Start Sofar packet sniffer")

    sofar_sniffer(opt_ip, opt_if, opt_log, opt_cap, opt_cmd)
