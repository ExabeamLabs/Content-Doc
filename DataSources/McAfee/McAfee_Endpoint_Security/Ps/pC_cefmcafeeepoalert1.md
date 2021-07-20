#### Parser Content
```Java
{
Name = cef-mcafee-epo-alert-1
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF""", """|McAfee|Rogue System Sensor|""", """|Rogue System|""", """Detected Rogue System""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wagt=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wcs4=({os}.+?)\s{1,100}(\w+=|$)""",
    """\Wseverity=({alert_severity}.+?)\s{1,100}(\w+=|$)""",
    """\WcategoryTechnique=({threat_category}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
  ]
}
```