#### Parser Content
```Java
{
Name = xml-4624-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4624"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4624<""", """An account was successfully logged on""", """<Data Name\=""", """WorkstationName""" ]
  Fields = [
    """<TimeCreated SystemTime\\='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """<Computer>({host}[^<>]+)</Computer>""",
    """<Provider Name\\='({provider_name}[^'"]+)""",
    """<EventID[^<]*?>({event_code}\d+)""",
    """({event_name}An account was successfully logged on)""",
    """<Data Name\\='SubjectUserSid'>(-|({user_sid}.+?))<""",
    """<Data Name\\='SubjectUserName'>(-|({user}.+?))<""",
    """<Data Name\\='SubjectDomainName'>(-|({domain}.+?))<""",
    """<Data Name\\='SubjectLogonId'>(-|({logon_id}.+?))<""",
    """<Data Name\\='TargetUserName'>(SYSTEM|({target_user}[^<]+))<""",
    """<Data Name\\='TargetDomainName'>({target_domain}[^<]+)<""",
    """<Data Name\\='LogonType'>({logon_type}\d+)<""",
    """<Data Name\\='TargetUserSid'>({target_user_sid}[^<]+)<""",
    """<Data Name\\='TargetLogonId'>({target_logon_id}[^<]+)<""",
    """<Data Name\\='ProcessName'>(-|({process}({process_directory}[^<>]*?[\\\/]+)?({process_name}[^<>\\\/]+)))<""",
    """<Data Name\\='ProcessId'>({pid}[^<]+?)\s*<""",
    """<Execution ProcessID\\='({pid}[^'"]+)""",
    """<Data Name\\='IpAddress'[^<>]*?>(-|({src_ip}[A-Fa-f:\d.]+))""",
    """<Data Name\\='LogonProcessName'>({auth_process}[^\s<]+)""",
    """<Data Name\\='AuthenticationPackageName'>({auth_package}[^<]+)<""",
    """<Data Name\\='WorkstationName'>([A-Fa-f:\d.]+|-|({src_host}[^<]+))<""",
    """<Keywords>({outcome}.+?)</Keywords>"""
  ]
  DupFields = ["host->dest_host"]
}
```