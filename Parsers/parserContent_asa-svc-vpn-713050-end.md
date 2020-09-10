#### Parser Content
```Java
{
Name = asa-svc-vpn-713050-end
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Sumo
  DataType = "vpn-end"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ " Connection terminated for " , "-713050" ]
  Fields = [
    """exabeam_raw=.+?({time}\w+ \d+ \d\d\d\d \d+:\d+:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+).+?%ASA""",
    """IP\s*=\s*({src_ip}[A-Fa-f:\d.]+)""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
   ]
}
```