#### Parser Content
```Java
{
Name = o365-failed-sign-in-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""failureReason":""", """flexString1=sign-in""", """destinationServiceName=Office 365""", """|security-threat-detected|"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"createdDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """requestClientApplication=({app}.+?)\s*(\w+=|$)""",
    """"userPrincipalName":"({user_email}[^@"\s]+?@[^"\s]+?)""""   
    """"id":"({alert_id}[^"]+?)""""
    """"failureReason":"({failure_reason}[^"]+?)""""
    """"ipAddress":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))""""
  ]
}
```