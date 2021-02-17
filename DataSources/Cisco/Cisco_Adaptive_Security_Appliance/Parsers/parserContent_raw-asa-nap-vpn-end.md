#### Parser Content
```Java
{
Name = raw-asa-nap-vpn-end
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Session is being torn down", "-713259" ]
  Fields = [
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+).+?%ASA""",
    """({time}\w+ \d+ \d\d\d\d \d+:\d+:\d+)""",
    """Username = ({user}[^,@]+?)(,|\s*$)""",
    """IP = ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
  ]
}
```