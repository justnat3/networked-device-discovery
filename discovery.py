import socket
from ipaddress import IPv4Network, AddressValueError
import logging
import sys

root_logging = logging.getLogger(__file__)
root_logging.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.ERROR)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root_logging.addHandler(handler)

results = list()
data = None


def discovery_by_cidr_via_ssh():
    global data
    global results
    try:
        # reading a CIDR block
        addresses_: list = [
            str(ip)
            for ip in IPv4Network(
                input("Insert a non-spaced, not host-specified Address Block: ")
            )
        ]
    except AddressValueError:
        # exit if the user put in an invalid block
        print("Found invalid block with host-bit set or just invalid address block")
        sys.exit(1)

    for address in addresses_:

        # Create a UDP, INET socket with a Non_Zero timeout
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        try:
            s.connect((address, 22))
        except socket.timeout:
            # this is hit on a timeout
            root_logging.debug("{:<5}::TIMEOUT".format(address))
        except OSError as err:
            # this is typically a error throw for windows. Just log it as critical and it will show.
            root_logging.critical(
                "{:<5}::UNEXPECTED_ERROR::{:<5}".format(address, str(err))
            )

        try:
            # read into 1024 byte buffer
            data = s.recv(1024)
        except Exception as err:
            # this may be hit on a time out
            root_logging.debug("{:<5}::{:<5}".format(str(address), str(err)))

        if data:
            # * 98:206 -> method::KeyExchange
            # * 0:16   -> proto::ssh::version

            """  Reference to RFC4253 on protoversion strings 
            SSH-protoversion-softwareversion SP comments CR LF
            "this identification string does not contain the option 'comments' string" \
            "and is thus terminated by a CR and LF immediately after the 'softwareversion' string."
            """
            proto_length = str(data).index(r"\r\n")

            results.append(
                {
                    "address": address,
                    "method": data[98:206],
                    "proto": data[:proto_length],
                }
            )

            data = None
        else:
            root_logging.debug("no data found for {:<5}".format(address))
        s.close()
    return results


if __name__ == "__main__":
    discovery_by_cidr_via_ssh()
