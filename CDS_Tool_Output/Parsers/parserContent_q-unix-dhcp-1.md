#### Parser Content
```Java
{
Name = q-unix-dhcp-1
  Vendor = Unix
  Lms = QRadar
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ """dhcpd""", """,Renewed,""" ]
  Fields = [ """\sexabeam_endTime=({time}\d+)""",
    """\s({host}[^\s]+)\s+dhcpd""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,({dest_host}[^,]+)"""
  ]
  DupFields = [ "dest_host->user" ]
}
```