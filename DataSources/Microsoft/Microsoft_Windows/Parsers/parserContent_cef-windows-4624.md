#### Parser Content
```Java
{
Name = cef-windows-4624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4624"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4624"""", """An account was successfully logged on""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]+?)\s{0,100}"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s{0,100}"""",
    """"subjectUserName":"({user}[^"\s]+?)\s{0,100}"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s{0,100}"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s{0,100}"""",
    """"logonType":"({logon_type}[^"]+?)\s{0,100}"""",
    """"logonProcessName":"({auth_process}[^"]+?)\s{0,100}"""",
    """"authenticationPackageName":"({auth_package}[^"]+?)\s{0,100}"""",
    """"workstationName":"({src_host_windows}[^"]+?)\s{0,100}"""",
    """"processName":"(?:-|({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?))\s{0,100}"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"ipPort":"({src_port}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```