#### Parser Content
```Java
{
Name = o365-url-click-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""Operation":"TIUrlClickData"""", """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|audit-event|"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"Id":"({alert_id}[^"]+)"""",
    """requestClientApplication=({process}.+?)\s{0,100}(\w+=|$)""",
    """"EventDeepLink":"\s{0,100}({additional_info}[^"]+)"""",
    """"Workload":"({alert_type}[^"]+)""",
    """"Operation":"({alert_name}[^"]+)""",
    """"UserId":"({user_email}[^@"\s]+?@[^"\s]+?)""""   
    """"UserIp":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))"""" 
    """"Url":"({malware_url}[^"]+?)""""
  ]
  DupFields = [ "process->vendor_value" ]
}
```