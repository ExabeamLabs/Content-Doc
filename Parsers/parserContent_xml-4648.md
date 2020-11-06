#### Parser Content
```Java
{
Name = xml-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4648</EventID>""", """='ProcessName'"""]
    Fields = [
      """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]+)<\/Data>""",
      """<Data Name(\\)?='SubjectUserName'>({user}[^<]+)<\/Data>""",
      """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+)</Data>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
      """<Data Name(\\)?='TargetUserName'>({account}[^<]+)</Data>""",
      """<Data Name(\\)?='TargetDomainName'>({account_domain}[^<]+)</Data>""",
      """<Data Name(\\)?='TargetServerName'>({dest_host}[^<]+)</Data>""",
      """<Data Name(\\)?='ProcessId'>({process_id}[^<]+)</Data>""",
      """<Data Name(\\)?='ProcessName'>({process}({directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/"]+?))<\/Data>""",
      """<Data Name(\\)?='IpAddress'>({src_ip}[a-fA-F:\d.]+)</Data>""",
      """<Data Name(\\)?='TargetInfo'>({dest_service}[^<]+)</Data>""",
    ]
    DupFields = ["directory->process_directory"]
  }
```