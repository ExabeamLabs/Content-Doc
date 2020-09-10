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
    """"EventID"*:({event_code}[^,]+)""",
    """"EventTime"*:"*({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"Hostname"*:"*({host}[^"]+)"""",
    """"EventType"*:"*({outcome}[^"]+)""",
    """"Domain"*:"*({domain}[^"]+)""",
    """"Severity"*:"*({severity}[^"]+)"""",
    """"SeverityValue"*:({severity}[^,]+)""",
    """"AccountName"*:"*({user}[^"]+)"""",
    """"SubjectUserSid"*:"*({user_sid}[^"]+)"""",
    """"SubjectUserName"*:"*({user}[^"]+)"""",
    """"SubjectDomainName"*:"*({domain}[^"]+)"""",
    """"LogonID"*:"*({logon_id}[^"]+)"""",
    """"ProcessId"*:"*(\\t)*({process_id}[^\\]+)"""",
    """"Category"*:"*({event_name}[^"]+)""",
    """"Message"*:"*({event_name}[^.]+)""",
    """"Message"*:"*The session setup from the computer ({src_host}[^\s]+)\s""",
    """The following error occurred:(\s|\\r|\\n)*({failure_reason}[^."]+)"""
  ]
}
```