#### Parser Content
```Java
{
Name = cef-unix-dhcp
  Vendor = Unix
  Product = Unix dhcpd
  Lms = ArcSight
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix||arcsight:""", "dhcpd" ]
  Fields = [ """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[\w.\-]{1,2000})""",
    """DHCPREQUEST for ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) from.+?\(({dest_host}[^\)]{1,2000})""",
    """Added new forward map from ({dest_host}.+?) to ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,({dest_host}[^,]{1,2000})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```