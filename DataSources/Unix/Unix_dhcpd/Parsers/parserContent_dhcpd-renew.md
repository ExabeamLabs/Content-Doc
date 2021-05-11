#### Parser Content
```Java
{
Name = dhcpd-renew
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd: """, """ RENEW """ ]
  Fields = [
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]+) dhcpd:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}RENEW)""",
    """\sIP=({dest_ip}[a-fA-F\d.:]+)""",
    """\sMAC=({dest_mac}[a-fA-F\d.:]+)""",
    """\sHOSTNAME=(?:nil|({dest_host}.+?))\s{1,100}\w+=""",
    """\sDOMAIN=({domain}.+?)\s{1,100}\w+=""",
    """\sLEASETIME=({lease_time}.+?)\s{1,100}\w+="""
  ]
  DupFields = [ "dest_host->user" ]
}
```