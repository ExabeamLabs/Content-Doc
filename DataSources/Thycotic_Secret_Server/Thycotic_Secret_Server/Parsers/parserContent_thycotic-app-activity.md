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
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]+) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)\s\w+=""",
    """\ssuser=(({domain}[^\\=]+)(\\)+)?({user}[^=]+?)\s{1,100}\w+=""",
    """({app}Thycotic Software)"""
    """\sfname=({object}[^=]+?)\s{1,100}\w+=""",
    """\sContainer Name:\s{0,100}({resource}[^=]+?)\s{0,100}(?:\([^\)]*?\))?\s{1,100}(\w+=|\w+:|$)""",
    """Action: \[({activity}[^\]]+)\]""",
    """\sfileType=({additional_info}[^=]+?)\s\w+="""
  ]
}
```