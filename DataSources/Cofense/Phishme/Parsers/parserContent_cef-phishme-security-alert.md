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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({alert_type}Rule Match)""",
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wduser=(|({user_email}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```