#### Parser Content
```Java
{
Name = cef-windows-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4776"""", """attempted to validate the credentials for an account""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetUserName":"({user}[^"\s@]+?)\s*"""",
    """"targetUserName":"({user_email}[^"\s@]+@[^"\s@]+?)\s*"""",
    """"workstation":"({dest_host}[^"\s]+?)\s*"""",
    """"status":"({result_code}[^"]+?)\s*"""",
  ]
}
```