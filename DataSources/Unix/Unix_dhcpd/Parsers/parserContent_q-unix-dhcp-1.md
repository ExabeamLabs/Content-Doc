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
    """\sexabeam_endTime=({time}\d{1,100})""",
    """\s({host}[^\s]{1,2000})\s{1,100}dhcpd""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,(|({dest_host}[^,]{1,2000}))"""
  ]
  DupFields = [ "dest_host->user" ]
}
```