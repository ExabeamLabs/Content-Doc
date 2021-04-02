#### Parser Content
```Java
{
Name = q-unix-dhcp-1
  Vendor = Unix
  Product = Unix dhcpd
  Lms = QRadar
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ """dhcpd""", """,Renewed,""" ]
  Fields = [ 
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sexabeam_endTime=({time}\d+)""",
    """\s({host}[^\s]+)\s+dhcpd""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,(|({dest_host}[^,]+))"""
  ]
  DupFields = [ "dest_host->user" ]
}
```