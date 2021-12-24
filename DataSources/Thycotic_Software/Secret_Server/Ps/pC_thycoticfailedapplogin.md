#### Parser Content
```Java
{
Name = thycotic-failed-app-login
  Vendor = Thycotic Software
  Product = Secret Server
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Thycotic Software|Secret Server|""","""|USER - LOGINFAILURE|""",""" Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]{1,2000}) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\sduser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """Details:\s{0,100}({failure_reason}.+?)\s\w+=""",
    """({app}Thycotic Software)"""
  ]


}
```