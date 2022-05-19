#### Parser Content
```Java
{
Name = o365-signin-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions= [ """destinationServiceName =Office 365""", """"riskEventType":"AnonymousIpRiskEvent"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"riskEventDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """requestClientApplication=({process}.+?)\s{0,100}(\w+=|$)""",
    """"userPrincipalName":"({user_email}[^@"\s]{1,2000}?@[^"\s]{1,2000}?)""""
    """"id":"({alert_id}[^"]{1,2000}?)""""
    """"riskLevel":"({alert_severity}[^"]{1,2000}?)""""
    """"ipAddress":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))""""
    """"riskEventType":"({alert_name}[^"]{1,2000}?)""""
    """({alert_type}anomalous-signin)"""
    """"location":\{"({additional_info}.*?)\}+"""
  ]
  DupFields = [ "process->vendor_value", "alert_type->alert_name" ] 


}
```