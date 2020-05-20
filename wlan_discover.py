#!/usr/bin/python


from binascii import hexlify
from winreg import (ConnectRegistry, OpenKey, QueryValueEx,
                    EnumKey, CloseKey, HKEY_LOCAL_MACHINE)


def print_networks():
    print("\nPrevious APs you were connected with : ")

    root = ConnectRegistry(None, HKEY_LOCAL_MACHINE)

    for i in range(100):

        net = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
              r"\NetworkList\Signatures\Unmanaged"
        key = OpenKey(root, net)

        try:
            hkey = OpenKey(key, str(EnumKey(key, i)))

            # Get the value from DefaultGatewayMac (winreg binary)
            # and decode it to a string value
            value = QueryValueEx(hkey, "DefaultGatewayMac")[0]
            mac_address = hexlify(value).decode()

            if mac_address is not None:
                # Get the profile guid needed to search for the profile name
                profile = QueryValueEx(hkey, "ProfileGuid")[0]

                # Closing previously opened keys
                # Reopened in the next iteration
                CloseKey(hkey)
                CloseKey(key)

                net = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
                      r"\NetworkList\Profiles"
                net = net + "\\" + profile

                key = OpenKey(root, net)

                # Get the profile name (network name) as a string
                net_name = QueryValueEx(key, "ProfileName")[0]
                # Get both the first connection and last connection dates from the profile
                date_fc = QueryValueEx(key, "DateCreated")[0]
                date_lc = QueryValueEx(key, "DateLastConnected")[0]

                # Function created specifically to decode dates from win registry
                def get_winreg_date(date_query):
                    year  = str(int(hexlify(date_query[1::-1]), 16))
                    month = str(int(hexlify(date_query[3:1:-1]), 16))
                    day   = str(int(hexlify(date_query[7:5:-1]), 16))
                    hour  = str(int(hexlify(date_query[9:7:-1]), 16))
                    min   = str(int(hexlify(date_query[11:9:-1]), 16))
                    sec   = str(int(hexlify(date_query[13:11:-1]), 16))

                    return day + "/" + month + "/" + year + " " + \
                           hour + ":" + min + ":" + sec

                print("\n[" + str(i+1) +"] " +  net_name +
                      "\n+ MAC address        " + mac_address +
                      "\n+ First connection   " + get_winreg_date(date_fc) +
                      "\n+ Last connection    " + get_winreg_date(date_lc))

            # Reopened in the next iteration
            CloseKey(key)
        except WindowsError:
            break


if __name__ == '__main__':
    print_networks()
