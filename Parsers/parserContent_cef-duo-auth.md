#### Parser Content
```Java
{
Name = cef-duo-auth
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Duo|MFA Service|""", """reason=""", """|authentication-factor-executed|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wreason=({failure_reason}.+?)(\s+\w+=|\s*$)""",
    """\Woutcome=({outcome}.+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wduser=({user}.+?)(\s+\w+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wcs4=({os}.+?)(\s+\w+=|\s*$)""",
    """\Wshost=({src_host}.+?)(\s+\w+=|\s*$)""",
    """\WrequestClientApplication=({browser}.+?)(\s+\w+=|\s*$)""",
    """\WflexString1=(?:n\/a|({factor}.+?))(\s+\w+=|\s*$)""",
    """\Wcs6=({new_enrollment}.+?)(\s+\w+=|\s*$)""",
  ]
}
```