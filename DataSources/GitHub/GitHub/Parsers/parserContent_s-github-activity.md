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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({host}[\w.\-]{1,2000})\s{1,100}github_auth:""",
    """\Wlogin=(nil|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrepo=(nil|({object}.+?)(.git)?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Waction=({activity}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprotocol=({protocol}[^\s]{1,2000})""",
    """({app}github)""",
    """\Wat=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmessage="({failure_reason}[^"]{1,2000})".*?\sat=failure""",
    """\Wip=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wuser_agent="({user_agent}[^"]{1,2000})""""
  ]
}
```