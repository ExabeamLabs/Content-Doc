#### Parser Content
```Java
{
Name = cef-unix-dhcp
  Vendor = Unix
  Lms = ArcSight
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix||arcsight:""", "dhcpd" ]
  Fields = [ """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[\w.\-]+)""",
    """DHCPREQUEST for ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) from.+?\(({dest_host}[^\)]+)""",
    """Added new forward map from ({dest_host}.+?) to ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,({dest_host}[^,]+)"""
  ]
  DupFields = [ "dest_host->user" ]
}
```