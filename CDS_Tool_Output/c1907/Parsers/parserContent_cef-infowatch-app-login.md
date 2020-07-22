#### Parser Content
```Java
{
Name = cef-infowatch-app-login
  Vendor = InfoWatch
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|DLP TM6 Audit|""", """cat=User""", """act=login""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=({user}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuid=({user_fullname}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wad\.user__email=({user_email}.+?)(\s+[\w\.]+=|\s*$)""",
    """"hostname":"({host}[^"]+)"""",
    """"ip":"({dest_ip}[^"]+)"""",
    """"login":"({user}[^"]+)"""",
  ]
  DupFields = [ "host->app" ]
}
```