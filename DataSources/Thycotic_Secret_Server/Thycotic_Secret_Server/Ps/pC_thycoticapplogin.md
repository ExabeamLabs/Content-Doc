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
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]{1,2000}) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\sduser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """({app}Thycotic Software)"""
  ]
}
```