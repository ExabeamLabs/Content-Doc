#### Parser Content
```Java
{
Name = dhcpd-renew
  Vendor = Unix
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd: """, """ RENEW """ ]
  Fields = [
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w.\-]+) dhcpd:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}RENEW)""",
    """\sIP=({dest_ip}[a-fA-F\d.:]+)""",
    """\sMAC=({dest_mac}[a-fA-F\d.:]+)""",
    """\sHOSTNAME=(?:nil|({dest_host}.+?))\s+\w+=""",
    """\sDOMAIN=({domain}.+?)\s+\w+=""",
    """\sLEASETIME=({lease_time}.+?)\s+\w+="""
  ]
  DupFields = [ "dest_host->user" ]
}

{
  Name = syslog-dhcpd-1
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"program":"dhcpd"""", """"logT":"DHCP-LINUX"""", """"message":"DHCPACK on""" ]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"host":"({host}[^"]+)""",
    """"message":"DHCPACK on ({dest_ip}[A-Fa-f:\d.]+) to ({dest_mac}\S+)( \(({dest_host}[^\s\)]+)\))? via ({dest_interface}[^\\"]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```