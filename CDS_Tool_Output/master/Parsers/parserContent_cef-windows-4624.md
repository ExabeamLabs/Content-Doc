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
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*"""",
    """"logonType":"({logon_type}[^"]+?)\s*"""",
    """"logonProcessName":"({auth_process}[^"]+?)\s*"""",
    """"authenticationPackageName":"({auth_package}[^"]+?)\s*"""",
    """"workstationName":"({src_host_windows}[^"]+?)\s*"""",
    """"processName":"(?:-|({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?))\s*"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"ipPort":"({src_port}\d+)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```