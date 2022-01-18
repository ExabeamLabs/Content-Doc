#### Parser Content
```Java
{
Name = o365-url-click-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""Operation":"TIUrlClickData"""", """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName =Office 365""", """|audit-event|"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"Id":"({alert_id}[^"]{1,2000})"""",
    """requestClientApplication=({process}.+?)\s{0,100}(\w+=|$)""",
    """"EventDeepLink":"\s{0,100}({additional_info}[^"]{1,2000})"""",
    """"Workload":"({alert_type}[^"]{1,2000})""",
    """"Operation":"({alert_name}[^"]{1,2000})""",
    """"UserId":"({user_email}[^@"\s]{1,2000}?@[^"\s]{1,2000}?)""""   
    """"UserIp":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))"""" 
    """"Url":"({malware_url}[^"]{1,2000}?)""""
  ]
  DupFields = [ "process->vendor_value" ]


}
```