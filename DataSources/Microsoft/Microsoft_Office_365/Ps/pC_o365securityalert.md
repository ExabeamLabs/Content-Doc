#### Parser Content
```Java
{
Name = o365-security-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """AlertTriggered""", """AlertType=""", """AlertId""", """destinationServiceName =Office 365"""]
  Fields = [
   """"(ts|CreationTime)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]{1,2000})""",
   """"f3u":"({user_email}[^"]{1,2000})""",
   """"ad":"({additional_info}[^"]{1,2000})""",
   """"(Name|an)":"({alert_name}[^"]{1,2000})""",
   """"AlertId":"({alert_id}[^"]{1,2000})""""
   """"(sev|Severity)":"({alert_severity}[^"]{1,2000})""",
   """"AlertType":"({alert_type}[^"]{1,2000})"""",
   """requestClientApplication=({process}.*?)\s\w+="""
  ]
  DupFields = ["process->process_name"]


}
```