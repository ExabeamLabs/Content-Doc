#### Parser Content
```Java
{
Name = cef-trendmicro-database-failed-login
  Vendor = Trend Micro
  Product = Trend Micro
  Lms = ArcSight
  DataType = "database-failed-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
  Conditions = [ """CEF:""", """|Database Server - Microsoft SQL|""", """Login failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """Login failed for user\s{0,100}'(({domain}[^']+?)\\+)?({user}[^'\\]+)'""",
    """Reason:\s{0,100}({failure_reason}.+?)\s{0,100}\.""",
  ]
}
```