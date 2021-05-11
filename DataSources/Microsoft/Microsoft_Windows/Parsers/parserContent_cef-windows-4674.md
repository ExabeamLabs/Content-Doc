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
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]+?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^\s"]+)""",
    """"subjectLogonId":"({logon_id}[^\s"]+)""",
    """"objectServer":"(-|({object_server}[^\s"]+))""",
    """"subjectUserName":"(-|({user}[^\s"]+))"""",
    """"subjectDomainName":"(-|({domain}[^\s"]+))"""",
    """"processName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s{0,100}"""",
    """"privilegeList":"({privileges}[^"]+?)\s{0,100}""""
  ]
   DupFields = ["host->dest_host","directory->process_directory"]
}
```