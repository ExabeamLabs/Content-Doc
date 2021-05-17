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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """<TimeCreated SystemTime=('+|"{1,20})({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}\d{1,100})<""",
    """<Execution ProcessID='({process_id}\d{1,100})'\s{1,100}ThreadID='({thread_id}\d{1,100})'""",
    """<Computer>({dest_host}[^<]{1,2000})<""",
    """<Security UserID=('+|"{1,20})({user_sid}[^'"]{1,2000})'""",
    """<User>(({domain}\S+)\\+)?({user}[^<]{1,2000})<""",
    """<SessionID>({session_id}\d{1,100})<""",
    """<Address>({src_ip}[a-fA-F\d.-]{1,2000})<""",
  ]
}
```