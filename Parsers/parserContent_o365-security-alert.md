#### Parser Content
```Java
{
Name = o365-security-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """AlertTriggered""", """AlertType=""", """AlertId""", """destinationServiceName=Office 365"""]
  Fields = [
   """"(ts|CreationTime)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]+)""",
   """"f3u":"({user_email}[^"]+)""",
   """"ad":"({additional_info}[^"]+)""",
   """"(Name|an)":"({alert_name}[^"]+)""",
   """"AlertId":"({alert_id}[^"]+)""""
   """"(sev|Severity)":"({alert_severity}[^"]+)""",
   """"AlertType":"({alert_type}[^"]+)"""",
   """requestClientApplication=({process}.*?)\s\w+="""
  ]
  DupFields = ["process->process_name"]
}
```