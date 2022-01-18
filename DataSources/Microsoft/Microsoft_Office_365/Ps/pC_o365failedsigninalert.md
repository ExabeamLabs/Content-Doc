#### Parser Content
```Java
{
Name = o365-failed-sign-in-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""failureReason":""", """flexString1=sign-in""", """destinationServiceName =Office 365""", """|security-threat-detected|"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"createdDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """requestClientApplication=({app}.+?)\s{0,100}(\w+=|$)""",
    """"userPrincipalName":"({user_email}[^@"\s]{1,2000}?@[^"\s]{1,2000}?)""""   
    """"id":"({alert_id}[^"]{1,2000}?)""""
    """"failureReason":"({failure_reason}[^"]{1,2000}?)""""
    """"ipAddress":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))"""",
    """"userPrincipalName":"({user_email}[^"]{1,2000})""",
  ]


}
```