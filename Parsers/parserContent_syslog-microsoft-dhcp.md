#### Parser Content
```Java
{
Name = syslog-microsoft-dhcp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|DHCP|""", """|Dhcp_Server|""" ]
  Fields = [ """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```