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
    """"EventID"{0,20}:({event_code}[^,]{1,2000})""",
    """"EventTime"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"Hostname"{0,20}:"{0,20}({host}[^"]{1,2000})"""",
    """"EventType"{0,20}:"{0,20}({outcome}[^"]{1,2000})""",
    """"Domain"{0,20}:"{0,20}({domain}[^"]{1,2000})""",
    """"Severity"{0,20}:"{0,20}({severity}[^"]{1,2000})"""",
    """"SeverityValue"{0,20}:({severity}[^,]{1,2000})""",
    """"AccountName"{0,20}:"{0,20}({user}[^"]{1,2000})"""",
    """"SubjectUserSid"{0,20}:"{0,20}({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName"{0,20}:"{0,20}({user}[^"]{1,2000})"""",
    """"SubjectDomainName"{0,20}:"{0,20}({domain}[^"]{1,2000})"""",
    """"LogonID"{0,20}:"{0,20}({logon_id}[^"]{1,2000})"""",
    """"ProcessId"{0,20}:"{0,20}(\\t)*({process_id}[^\\]{1,2000})"""",
    """"Category"{0,20}:"{0,20}({event_name}[^"]{1,2000})""",
    """"Message"{0,20}:"{0,20}({event_name}[^.]{1,2000})""",
    """"Message"{0,20}:"{0,20}The session setup from the computer ({src_host}[^\s]{1,2000})\s""",
    """The following error occurred:(\s|\\r|\\n)*({failure_reason}[^."]{1,2000})"""
  ]
}
```