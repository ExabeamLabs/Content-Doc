#### Parser Content
```Java
{
Name = xml-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ElasticSearch
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4624</EventID>""", """<Data Name="""]
    Fields = [
      """SystemTime=('|")({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}An account was successfully logged on)""",
      """<Computer>([^<>]+?[\\\/]+)?({host}({dest_host}[\w\-]+)[^<]*)</Computer>""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Data Name=('|")LogonType('|")>({logon_type}\d+)</Data>""",
      """<Data Name=('|")TargetUserName('|")>(SYSTEM|({user}[^<]+))</Data>""",
      """<Data Name=('|")TargetDomainName('|")>((?i)NT AUTHORITY|-|({domain}[^<]+))<\/Data>""",
      """<Data Name=('|")ProcessName('|")>(?:-|({process}({process_directory}[^<>]*?[\\\/]+)?({process_name}[^<>\\\/]+)))</Data>""",
      """<Data Name=('|")IpAddress('|")[^<>]*?>(?:-|::1|({src_ip}[A-Fa-f\d.:]+))</Data>""",
      """<Data Name=('|")LogonProcessName('|")>({auth_process}[^\s<]+)""",
      """<Data Name=('|")AuthenticationPackageName('|")>({auth_package}[^<]+)</Data>""",
      """<Data Name=('|")TargetLogonId('|")>({logon_id}[^<]+)</Data>""",
      """<Data Name=('|")TargetUserSid('|")>({user_sid}[^<]+)</Data>""",
      """<Data Name=('|")WorkstationName('|")>([A-Fa-f:\d.]+|-|({src_host_windows}[^<]+?))\s*</Data>""",
      """EventRecordID>({record_id}[^<]+)<"""
    ]
    DupFields = ["process_directory->directory"]
  }
```