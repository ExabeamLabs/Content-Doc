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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[\w\-.]{1,2000})\s"""
    """incident,"{0,20}({app}[^",]{1,2000})",({alert_severity}\d(\.\d)?)"{0,20},({alert_id}[\dA-Fa-f]{1,2000})"{0,20}"{0,20},"""
    """\d{1,100}:\d{1,100}Z,([^,]{0,2000},){3}"?({user_email}[^@]{1,2000}@[^\.]{1,2000}[^,"]{1,2000})""",
    """"{1,20}({alert_name}[^"]{1,2000})"{1,20},EXTERNAL,""",
    """,incident,"?({alert_type}[^",]{1,2000})""",
    """incident,"{0,20}({app}[^",]{1,2000})",({alert_severity}\d(\.\d)?)"{0,20},({alert_id}[\dA-Fa-f]{1,2000})"{0,20},[\dA-Fa-f]{1,2000}"{0,20},"{0,20}\s{0,100}({additional_info}[^,\s"]{1,2000})\s{0,100}"{0,20},([^,]{0,2000},)"""
  ]
}
```