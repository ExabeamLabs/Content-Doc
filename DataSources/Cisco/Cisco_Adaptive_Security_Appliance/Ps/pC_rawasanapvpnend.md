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
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """[\s\t]{1,2000}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}).+?%ASA""",
    """({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """Username = ({user}[^,@]{1,2000}?)(,|\s{0,100}$)""",
    """IP = ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
  ]
}
```