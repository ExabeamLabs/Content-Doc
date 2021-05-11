#### Parser Content
```Java
{
Name = json-windows-events-netlogon
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""NETLOGON""" , """"EventID":5805""","""failed to authenticate""" ]
  Fields = [
    """"EventID"{0,20}:({event_code}[^,]+)""",
    """"EventTime"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"Hostname"{0,20}:"{0,20}({host}[^"]+)"""",
    """"EventType"{0,20}:"{0,20}({outcome}[^"]+)""",
    """"Domain"{0,20}:"{0,20}({domain}[^"]+)""",
    """"Severity"{0,20}:"{0,20}({severity}[^"]+)"""",
    """"SeverityValue"{0,20}:({severity}[^,]+)""",
    """"AccountName"{0,20}:"{0,20}({user}[^"]+)"""",
    """"SubjectUserSid"{0,20}:"{0,20}({user_sid}[^"]+)"""",
    """"SubjectUserName"{0,20}:"{0,20}({user}[^"]+)"""",
    """"SubjectDomainName"{0,20}:"{0,20}({domain}[^"]+)"""",
    """"LogonID"{0,20}:"{0,20}({logon_id}[^"]+)"""",
    """"ProcessId"{0,20}:"{0,20}(\\t)*({process_id}[^\\]+)"""",
    """"Category"{0,20}:"{0,20}({event_name}[^"]+)""",
    """"Message"{0,20}:"{0,20}({event_name}[^.]+)""",
    """"Message"{0,20}:"{0,20}The session setup from the computer ({src_host}[^\s]+)\s""",
    """The following error occurred:(\s|\\r|\\n)*({failure_reason}[^."]+)"""
  ]
}
```