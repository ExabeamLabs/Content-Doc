#### Parser Content
```Java
{
Name = cef-windows-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4771"""", """Kerberos pre-authentication failed""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetSid":"({user_sid}[^"\s]+?)\s*"""",
    """"targetUserName":"({user}[^"\s]+?)\s*"""",
    """"serviceName":"({src_host}[\w\-.]+)\/({domain}[^\\\/\s"]+?)\s*"""",
    """"status":"({result_code}[^"]+?)\s*""""
  ]
}
```