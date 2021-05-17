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
    """exabeam_raw=.+?({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """[\s\t]{1,2000}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}).+?%ASA""",
    """IP\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
   ]
}
```