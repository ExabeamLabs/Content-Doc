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
    """cat=({alert_type}[^=]+?)\s*\w+=""",
    """resource=({dest_host}[^=]+?)\s*\w+=""",
    """application=({app}[^=]+?)\s*\w+=""",
    """message=({alert_name}[^"]+?)\s*$""",
    """usrName=(N\/A|(({domain}[^\\\s]+)\\)?({user}[^\s]+))\s*\w+=""",
    """LEEF\s({event_code}\d+)""",
    """sev=({alert_severity}\d+)"""
  ]
  DupFields = ["dest_host->host"]
}
```