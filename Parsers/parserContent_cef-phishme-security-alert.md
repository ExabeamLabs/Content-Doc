#### Parser Content
```Java
{
Name = cef-phishme-security-alert
  Vendor = Cofense
  Product = Phishme
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Cofense|Triage|""", """|Rule Match|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({alert_type}Rule Match)""",
    """\Wrt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wduser=(|({user_email}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\Wcs2=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
  ]
}
```