#### Parser Content
```Java
{
Name = cef-icdb-app-activity
  Vendor = ICDB
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|ICDB|ICDB|""", """requestContext=""" ]
    Fields = [
    """({app}ICDB)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[a-fA-F\d.:]+)""",
    """\Wdvchost=({host}[^=]+?)(\s+\w+=|\s*$)""",
    """\WrequestContext=[^\s=]*?;({target}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wshost=({src_host}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({domain}[^=]*?)[\\\/]+)?({user}[^=\\\/]+?)(\s+\w+=|\s*$)""",
    """\Wduid=({object}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wfname=({additional_info}[^=]+?)(\s+\w+=|\s*$)""",
  ]
}
```