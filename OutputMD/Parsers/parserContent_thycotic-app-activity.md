#### Parser Content
```Java
{
Name = thycotic-app-activity
  Vendor = Thycotic Secret Server
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [  """|Thycotic Software|Secret Server|""","""Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]+) CEF:""",
    """\srt=({time}\d+)""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s+\w+=""",
    """({app}Thycotic Software)"""
    """\sfname=([^\\=]+\\+)?({object}.+?)\s+\w+=""",
    """\sContainer Name:\s*({resource}.+?)(?:\(.*?\))?\s+(\w+=|\w+:|$)""",
    """Action: \[({activity}[^\]]+)\]""",
    """\sfileType=({additional_info}.+?)\s\w+="""
  ]
}
```