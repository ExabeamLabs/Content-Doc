#### Parser Content
```Java
{
Name = cef-windows-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4733"""", """Security Enabled""", """ Group Member Removed""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """"memberSid":"({account_id}[^"\s]+?)\s*"""",
    """"targetUserName":"({group_name}[^"\s]+?)\s*"""",
    """"targetDomainName":"({group_domain}[^"\s]+?)\s*"""",
    """"targetSid":"({group_id}[^"\s]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*""""
  ]
   DupFields = ["host->dest_host"]
}
```