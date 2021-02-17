#### Parser Content
```Java
{
Name = cef-windows-4768
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4768"""", """A Kerberos authentication ticket (TGT) was requested""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetSid":"({user_sid}[^"\s]+?)\s*"""",
    """"targetUserName":"({user}[^"\s]+?)\s*"""",
    """"targetDomainName":"({domain}[^"\s]+?)\s*"""",
    """"status":"({result_code}[^"]+?)\s*"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```