#### Parser Content
```Java
{
Name = cef-icdb-app-activity
  Vendor = ICDB
  Product = ICDB
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|ICDB|ICDB|""", """requestContext=""" ]
    Fields = [
    """({app}ICDB)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[a-fA-F\d.:]+)""",
    """\Wdvchost=({host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WrequestContext=[^\s=]*?;({target}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=({src_host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({domain}[^=]*?)[\\\/]+)?({user}[^=\\\/]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduid=({object}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=({additional_info}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```