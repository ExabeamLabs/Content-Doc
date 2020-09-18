#### Parser Content
```Java
{
Name = windows-rdp-login
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft-Windows-TerminalServices-LocalSessionManager""", """<EventID>21<""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """<TimeCreated SystemTime=('+|"+)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}\d+)<""",
    """<Execution ProcessID='({process_id}\d+)'\s+ThreadID='({thread_id}\d+)'""",
    """<Computer>({dest_host}[^<]+)<""",
    """<Security UserID=('+|"+)({user_sid}[^'"]+)'""",
    """<User>(({domain}\S+)\\+)?({user}[^<]+)<""",
    """<SessionID>({session_id}\d+)<""",
    """<Address>({src_ip}[a-fA-F\d.-]+)<""",
  ]
}
```