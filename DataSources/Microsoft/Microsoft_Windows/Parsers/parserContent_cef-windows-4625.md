#### Parser Content
```Java
{
Name = cef-windows-4625
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4625"""", """An account failed to log on""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"status":"({result_code}[^"]{1,2000}?)\s{0,100}"""",
    """"subStatus":"({result_code}[^"]{1,2000}?)\s{0,100}"""",
    """"failureReason":"({failure_reason}[^"]{1,2000}?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetDomainName":"({domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"subjectLogonId":"({logon_id}[^"\s]{1,2000}?)\s{0,100}"""",
    """"logonType":"({logon_type}[^"]{1,2000}?)\s{0,100}"""",
    """"logonProcessName":"({auth_process}[^"]{1,2000}?)\s{0,100}"""",
    """"authenticationPackageName":"({auth_package}[^"]{1,2000}?)\s{0,100}"""",
    """"workstationName":"({src_host_windows}[^"]{1,2000}?)\s{0,100}"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"ipPort":"({src_port}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```