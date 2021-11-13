#### Parser Content
```Java
{
Name = thycotic-app-activity
  Vendor = Thycotic Secret Server
  Product = Thycotic Secret Server
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [  """|Thycotic Software|Secret Server|""","""Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]{1,2000}) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})\s\w+=""",
    """\ssuser=(({domain}[^\\=]{1,2000})(\\)+)?({user}[^=]{1,2000}?)\s{1,100}\w+=""",
    """({app}Thycotic Software)"""
    """\sfname=({object}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sContainer Name:\s{0,100}({resource}[^=]{1,2000}?)\s{0,100}(?:\([^\)]{0,2000}?\))?\s{1,100}(\w+=|\w+:|$)""",
    """Action: \[({activity}[^\]]{1,2000})\]""",
    """\sfileType=({additional_info}[^=]{1,2000}?)\s\w+="""
  ]


}
```