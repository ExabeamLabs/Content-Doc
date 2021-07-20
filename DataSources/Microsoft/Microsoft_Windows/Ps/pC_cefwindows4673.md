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
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectUserName":"({user}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectDomainName":"({domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectLogonId":"({logon_id}[^"\s]{1,2000}?)\s{0,100}"""",
    """"objectServer":"({object_server}[^"]{1,2000}?)\s{0,100}"""",
    """"privilegeList":"({privileges}[^"]{1,2000}?)\s{0,100}"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```