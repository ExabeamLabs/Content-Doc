#### Parser Content
```Java
{
Name = cef-juniper-pulse-activity
  Vendor = Pulse Secure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Juniper|Pulse Secure""", """|Request Completed|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}[\w.\-]+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}[^\s]+)""",
    """\sspriv=({app}.+?)\s+\w+=""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sout=({bytes}\d+)""",
    """&Cmd\\=({activity}[^\s&]+)""",
    """&DeviceType\\=({additional_info}[^&]+)"""
  ]
}
```