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
  Fields = [ """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```