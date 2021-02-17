#### Parser Content
```Java
{
Name = palo-alto-dlp-alert
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ Aperture """, """,incident,""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s({host}[\w\-.]+)\s"""
    """incident,"*({app}[^",]+)",({alert_severity}\d(\.\d)?)"*,({alert_id}[\dA-Fa-f]+)"*"*,"""
    """\d+:\d+Z,([^,]*,){3}"?({user_email}[^@]+@[^\.]+[^,"]+)""",
    """"+({alert_name}[^"]+)"+,EXTERNAL,""",
    """,incident,"?({alert_type}[^",]+)""",
    """incident,"*({app}[^",]+)",({alert_severity}\d(\.\d)?)"*,({alert_id}[\dA-Fa-f]+)"*,[\dA-Fa-f]+"*,"*\s*({additional_info}[^,\s"]+)\s*"*,([^,]*,)"""
  ]
}
```