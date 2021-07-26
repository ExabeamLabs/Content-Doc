#### Parser Content
```Java
{
Name = cef-juniper-pulse-activity
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Juniper|Pulse Secure""", """|Request Completed|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[\w.\-]{1,2000})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}[^\s]{1,2000})""",
    """\sspriv=({app}.+?)\s{1,100}\w+=""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sout=({bytes}\d{1,100})""",
    """&Cmd\\=({activity}[^\s&]{1,2000})""",
    """&DeviceType\\=({additional_info}[^&]{1,2000})"""
  ]
}
```