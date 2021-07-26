#### Parser Content
```Java
{
Name = leef-appsense-process-alert
  Vendor = AppSense Application Manager
  Product = AppSense Application Manager
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ LEEF """, """AppSense Application Manager""", """message=""", """application=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]{1,2000})\s\S+\sLEEF""",
    """cat=({alert_type}[^=]{1,2000}?)\s{0,100}\w+=""",
    """resource=({dest_host}[^=]{1,2000}?)\s{0,100}\w+=""",
    """application=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """message=({alert_name}[^"]{1,2000}?)\s{0,100}$""",
    """usrName=(N\/A|(({domain}[^\\\s]{1,2000})\\)?({user}[^\s]{1,2000}))\s{0,100}\w+=""",
    """LEEF\s({event_code}\d{1,100})""",
    """sev=({alert_severity}\d{1,100})"""
  ]
  DupFields = ["dest_host->host"]
}
```