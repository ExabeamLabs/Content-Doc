#### Parser Content
```Java
{
Name = cef-windows-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4732"""", """Security Enabled""",       """Group Member Added""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetSid":"({group_id}[^"\s]+?)\s*"""",
    """"targetUserName":"({group_name}[^"\s]+?)\s*"""",
    """"targetDomainName":"({group_domain}[^"\s]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*""""
  ]
   DupFields = ["host->dest_host"]
}
```