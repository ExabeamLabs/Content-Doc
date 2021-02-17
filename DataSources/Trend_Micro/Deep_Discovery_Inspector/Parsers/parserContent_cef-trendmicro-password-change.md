#### Parser Content
```Java
{
Name = cef-trendmicro-password-change
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Discovery Inspector|""", """dvc=""", """Changed account password""" ]
  Fields = [
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wrt=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wduser=({user}[^\s]+)""",
    """\Woutcome=({outcome}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```