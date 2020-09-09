#### Parser Content
```Java
{
Name = cef-trendmicro-database-failed-login
  Vendor = Trend Micro
  Lms = ArcSight
  DataType = "database-failed-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
  Conditions = [ """CEF:""", """|Database Server - Microsoft SQL|""", """Login failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)""",
    """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$|\s*")""",
    """\Wshost=(|({src_host}.+?))(\s+\w+=|\s*$|\s*")""",
    """QUALITAS:\s*({host}[\w\.\-]+)""",
    """Login failed for user\s*'(({domain}[^']+?)\\+)?({user}[^'\\]+)'""",
    """Reason:\s*({failure_reason}.+?)\s*\.""",
  ]
}
```