#### Parser Content
```Java
{
Name = xml-8004
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>8004</EventID>""", """security policy Network Security:""", """Restrict NTLM:""" ]
  Fields = [
     """<Computer>({host}[^<>]+)</Computer>""",
     """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """<EventRecordID>({record_id}[^<>]+)<""",
     """Name='DomainName'>(NULL|({domain}[^<>]+))<""",
     """<EventID>({event_code}[^<>]+)</EventID>""",
     """({event_name}Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller)""",
     """<Execution ProcessID='({process_id}\d+)'""",
     """Name='SChannelName'>({resource}[^<>]+)<""",
     """Name='WorkstationName'>\\*({src_host}[^<>]+)<""",
     """Name='UserName'>(({user_email}[^@\s<>]+@[^@\s<>]+)|({user}[^<>]+))<""",
     """<Security UserID='({user_sid}[^<>\/']+)""",
     """security policy Network Security:\s*Restrict NTLM:\s*({policy}[^\.:]+)""",
  ]
}
```