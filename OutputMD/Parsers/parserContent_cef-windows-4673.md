#### Parser Content
```Java
{
Name = cef-windows-4673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4673"""", """A privileged service was called""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*"""",
    """"objectServer":"({object_server}[^"]+?)\s*"""",
    """"privilegeList":"({privileges}[^"]+?)\s*"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```