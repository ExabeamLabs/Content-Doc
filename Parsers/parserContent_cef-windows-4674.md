#### Parser Content
```Java
{
Name = cef-windows-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4674"""", """An operation was attempted on a privileged object""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^\s"]+)""",
    """"subjectLogonId":"({logon_id}[^\s"]+)""",
    """"objectServer":"(-|({object_server}[^\s"]+))""",
    """"subjectUserName":"(-|({user}[^\s"]+))"""",
    """"subjectDomainName":"(-|({domain}[^\s"]+))"""",
    """"processName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s*"""",
    """"privilegeList":"({privileges}[^"]+?)\s*""""
  ]
   DupFields = ["host->dest_host","directory->process_directory"]
}
```