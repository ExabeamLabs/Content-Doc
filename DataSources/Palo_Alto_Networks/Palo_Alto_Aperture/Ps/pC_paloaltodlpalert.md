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
    """incident,"{0,20}({app}[^",]{1,2000})",({alert_severity}\d(\.\d)?)"{0,20}
```