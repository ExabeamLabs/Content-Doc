#### Parser Content
```Java
{
Name = o365-signin-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|anomalous-signin|""", """"riskEventType":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """"riskEventDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """requestClientApplication=({process}.+?)\s*(\w+=|$)""",
    """"userPrincipalName":"({user_email}[^@"\s]+?@[^"\s]+?)""""
    """"id":"({alert_id}[^"]+?)""""
    """"riskLevel":"({alert_severity}[^"]+?)""""
    """"ipAddress":"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))""""
    """"riskEventType":"({alert_name}[^"]+?)""""
    """({alert_type}anomalous-signin)"""
    """"location":\{"({additional_info}.*?)\}+"""
  ]
  DupFields = [ "process->vendor_value", "alert_type->alert_name" ] 
}
```