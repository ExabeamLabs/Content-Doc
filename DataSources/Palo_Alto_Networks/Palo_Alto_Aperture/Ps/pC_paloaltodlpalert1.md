#### Parser Content
```Java
{
Name = palo-alto-dlp-alert-1
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ Aperture """, """,policy_violation,""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """,policy_violation,"{0,20}({app}[^,"]{1,2000})"{0,20}
```