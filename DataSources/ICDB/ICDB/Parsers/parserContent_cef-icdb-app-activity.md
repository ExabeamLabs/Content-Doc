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
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\Wdvchost=({host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WrequestContext=[^\s=]{0,2000}?;({target}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=({src_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=(({domain}[^=]{0,2000}?)[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduid=({object}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```