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
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """Security Enabled ({group_type}[^\s]{1,2000}) Group Member""",
    """"memberSid":"({account_id}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({group_name}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetDomainName":"({group_domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetSid":"({group_id}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectUserName":"({user}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectDomainName":"({domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectLogonId":"({logon_id}[^"\s]{1,2000}?)\s{0,100}""""
  ]
   DupFields = ["host->dest_host"]


}
```