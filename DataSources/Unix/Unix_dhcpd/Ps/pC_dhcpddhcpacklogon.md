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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000}) dhcpd:""",
    """({event_name}DHCPACK)""",
    """DHCPACK to ({dest_ip}[a-fA-F\d.:]{1,2000}) \((<no client hardware address>|({dest_mac}[a-fA-F\d.:]{1,2000}))\) via ({dest_interface}[^\s"]{1,2000})""",
    """DHCPACK on ({dest_ip}[a-fA-F\d.:]{1,2000}) to ({dest_mac}[a-fA-F\d.:]{1,2000}) (\(({dest_host}[\w\-.]{1,2000})\))?\s{0,100}via ({dest_interface}[^\s"]{1,2000})""",
  ]
  DupFields = [ "dest_host->user" ]
}
```