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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]+)\s\S+\sLEEF""",
    """cat=({alert_type}[^=]+?)\s{0,100}\w+=""",
    """resource=({dest_host}[^=]+?)\s{0,100}\w+=""",
    """application=({app}[^=]+?)\s{0,100}\w+=""",
    """message=({alert_name}[^"]+?)\s{0,100}$""",
    """usrName=(N\/A|(({domain}[^\\\s]+)\\)?({user}[^\s]+))\s{0,100}\w+=""",
    """LEEF\s({event_code}\d{1,100})""",
    """sev=({alert_severity}\d{1,100})"""
  ]
  DupFields = ["dest_host->host"]
}
```