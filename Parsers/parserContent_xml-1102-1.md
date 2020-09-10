#### Parser Content
```Java
{
Name = xml-1102-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["""<EventID>1102""", """LogFileCleared""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)""",
    """<Computer>({host}[^<]+)""",
    """<SubjectLogonId>({logon_id}[^<]+)""",
    """({event_code}1102)""",
    """({event_name}LogFileCleared)""",
    """<SubjectUserName>({user}[^<]+)""",
    """<SubjectUserSid>({user_sid}[^<]+)""",
    """<SubjectDomainName>({domain}[^<]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = windows-rdp-login
  Vendor = Microsoft Windows
  Product= Windows
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft-Windows-TerminalServices-LocalSessionManager""", """<EventID>21<""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """<TimeCreated SystemTime=('+|"+)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_id}\d+)<""",
    """<Execution ProcessID='({process_id}\d+)'\s+ThreadID='({thread_id}\d+)'""",
    """<Computer>({dest_host}[^<]+)<""",
    """<Security UserID=('+|"+)({user_sid}[^'"]+)'""",
    """<User>(({domain}\S+)\\+)?({user}[^<]+)<""",
    """<SessionID>({session_id}\d+)<""",
    """<Address>({src_ip}[a-fA-F\d.-]+)<""",
  ]
}
```