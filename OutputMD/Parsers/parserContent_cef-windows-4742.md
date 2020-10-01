#### Parser Content
```Java
{
Name = cef-windows-4742
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4742"""",  """A computer account was changed""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetSid":"({object}[^"\s]+?)\s*"""",
    """"targetUserName":"({target_user}[^"\s]+?)\s*"""",
    """"targetDomainName":"({object_dn}[^"\s]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*""""
  ]
   DupFields = ["host-> dest_host"]
}
```