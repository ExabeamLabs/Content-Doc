#### Parser Content
```Java
{
Name = dhcpd-dhcpack-logon
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd: DHCPACK """, """"message":"""", """"collector":"""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w.\-]+) dhcpd:""",
    """({event_name}DHCPACK)""",
    """DHCPACK to ({dest_ip}[a-fA-F\d.:]+) \((<no client hardware address>|({dest_mac}[a-fA-F\d.:]+))\) via ({dest_interface}[^\s"]+)""",
    """DHCPACK on ({dest_ip}[a-fA-F\d.:]+) to ({dest_mac}[a-fA-F\d.:]+) (\(({dest_host}[\w\-.]+)\))?\s*via ({dest_interface}[^\s"]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```