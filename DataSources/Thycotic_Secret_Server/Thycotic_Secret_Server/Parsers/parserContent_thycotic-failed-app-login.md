#### Parser Content
```Java
{
Name = thycotic-failed-app-login
  Vendor = Thycotic Secret Server
  Product = Thycotic Secret Server
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Thycotic Software|Secret Server|""","""|USER - LOGINFAILURE|""",""" Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]+) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\sduser=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """Details:\s{0,100}({failure_reason}.+?)\s\w+=""",
    """({app}Thycotic Software)"""
  ]
}
```