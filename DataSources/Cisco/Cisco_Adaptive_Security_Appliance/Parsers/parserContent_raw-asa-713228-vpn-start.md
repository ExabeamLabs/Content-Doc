#### Parser Content
```Java
{
Name = raw-asa-713228-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Assigned private IP address", "-713228","""%ASA-""" ]
  Fields = [
    """exabeam_time=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d{1,100} (\d\d\d\d )?\d{1,100}:\d{1,100}:\d{1,100}):""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-:]{1,2000})""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100}): Group =\s{0,100}({realm}[^,]{1,2000}),\s{0,100}Username = ({user}[^,@]{1,2000}?),?\s{1,100}IP = ({src_ip}[^\s,]{1,2000})[,\s]{1,2000}Assigned private IP address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to"""
  ]
}
```