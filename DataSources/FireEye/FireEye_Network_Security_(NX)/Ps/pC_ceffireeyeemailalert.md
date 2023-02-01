#### Parser Content
```Java
{
Name = cef-fireeye-email-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ "CEF:","""|FireEye|ETP|""", """suser=""", """mailcious email""" ]
  Fields = [
    """\|FireEye\|([^|]{0,2000}\|){3}({alert_type}[^|]{1,2000})""",
    """\|FireEye\|([^|]{0,2000}\|){4}({alert_severity}[^|]{1,2000})""",
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wfname=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationDnsDomain=({domain}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=({src_user}[^@\s]{1,2000})""",
    """\Wduser=({dest_user}[^@\s]{1,2000})""",
    """\Wduser=({user_email}[^@\s,]{1,2000}@[^@\s,]{1,2000})""",
    """\Wduser=({user}[^@\s,]{1,2000})""",
    """\Wcs1=({alert_name}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=({action}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs3=({subject}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)"""
  ]


}
```