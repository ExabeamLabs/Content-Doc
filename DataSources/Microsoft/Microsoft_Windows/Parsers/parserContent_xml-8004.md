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
     """<Computer>({host}[^<>]{1,2000})</Computer>""",
     """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """<EventRecordID>({record_id}[^<>]{1,2000})<""",
     """Name='DomainName'>(NULL|({domain}[^<>]{1,2000}))<""",
     """<EventID>({event_code}[^<>]{1,2000})</EventID>""",
     """({event_name}Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller)""",
     """<Execution ProcessID='({process_id}\d{1,100})'""",
     """Name='SChannelName'>({resource}[^<>]{1,2000})<""",
     """Name='WorkstationName'>\\*(NULL|({src_host}[^<>]{1,2000}))<""",
     """Name='UserName'>(({user_email}[^@\s<>]{1,2000}@[^@\s<>]{1,2000})|({user}[^<>]{1,2000}?))\s{0,100}<""",
     """<Security UserID='({user_sid}[^<>\/']{1,2000})""",
     """security policy Network Security:\s{0,100}Restrict NTLM:\s{0,100}({policy}[^\.:]{1,2000})""",
  ]
  DupFields = ["resource->dest_host"]
}
```