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
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"targetSid":"({group_id}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({group_name}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetDomainName":"({group_domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectUserName":"({user}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectDomainName":"({domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectLogonId":"({logon_id}[^"\s]{1,2000}?)\s{0,100}""""
  ]
   DupFields = ["host->dest_host"]


}
```