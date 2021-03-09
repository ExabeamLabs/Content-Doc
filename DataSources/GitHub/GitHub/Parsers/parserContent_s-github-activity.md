#### Parser Content
```Java
{
Name = s-github-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """github_auth""", """GitHub::Authentication""", """from=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}[\w.\-]+)\s+github_auth:""",
    """\Wlogin=(nil|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wrepo=(nil|({object}.+?)(.git)?)(\s+\w+=|\s*$)""",
    """\Waction=({activity}[^\s]+?)(\s+\w+=|\s*$)""",
    """\Wprotocol=({protocol}[^\s]+)""",
    """({app}github)""",
    """\Wat=({outcome}.+?)(\s+\w+=|\s*$)""",
    """\Wmessage="({failure_reason}[^"]+)".*?\sat=failure""",
    """\Wip=({src_ip}[a-fA-F:\d.]+)""",
    """\Wuser_agent="({user_agent}[^"]+)""""
  ]
}
```