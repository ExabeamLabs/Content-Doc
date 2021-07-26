#### Parser Content
```Java
{
Name = cef-trendmicro-app-login
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Discovery Inspector|""", """dvc=""", """User logged on""" ]
  Fields = [
    """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wduser=({user}[^\s]{1,2000})""",
    """\Woutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
```