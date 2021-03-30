#### Parser Content
```Java
{
Name = thycotic-app-login
  Vendor = Thycotic Secret Server
  Product = Thycotic Secret Server
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Thycotic Software|Secret Server|""","""|USER - LOGIN|""",""" Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]+) CEF:""",
    """\srt=({time}\d+)""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\sduser=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s+\w+=""",
    """({app}Thycotic Software)"""
  ]
}
```