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
    """\Wrt=({time}\d{1,100})""",
    """\Wreason=({failure_reason}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wduser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=({os}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WrequestClientApplication=({browser}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(?:n\/a|({factor}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs6=({new_enrollment}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```