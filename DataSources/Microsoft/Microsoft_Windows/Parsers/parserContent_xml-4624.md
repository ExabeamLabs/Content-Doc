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
      """<Computer>([^<>]{1,2000}?[\\\/]{1,2000})?({host}({dest_host}[\w\-]{1,2000})[^<]{0,2000})</Computer>""",
      """<EventID>({event_code}[^<]{1,2000})</EventID>""",
      """<Data Name=('|")LogonType('|")>({logon_type}\d{1,100})</Data>""",
      """<Data Name=('|")TargetUserName('|")>({user}[^<]{1,2000})</Data>""",
      """<Data Name=('|")TargetDomainName('|")>(-|({domain}[^<]{1,2000}))<\/Data>""",
      """<Data Name=('|")ProcessName('|")>(?:-|({process}({process_directory}[^<>]{0,2000}?[\\\/]{1,2000})?({process_name}[^<>\\\/]{1,2000})))</Data>""",
      """<Data Name=('|")IpAddress('|")[^<>]{0,2000}?>(?:-|({src_ip}[A-Fa-f\d.:]{1,2000}))</Data>""",
      """<Data Name=('|")LogonProcessName('|")>({auth_process}[^\s<]{1,2000})""",
      """<Data Name=('|")AuthenticationPackageName('|")>({auth_package}[^<]{1,2000})</Data>""",
      """<Data Name=('|")TargetLogonId('|")>({logon_id}[^<]{1,2000})</Data>""",
      """<Data Name=('|")TargetUserSid('|")>({user_sid}[^<]{1,2000})</Data>""",
      """<Data Name=('|")WorkstationName('|")>([A-Fa-f:\d.]{1,2000}|-|({src_host_windows}[^<]{1,2000}?))\s{0,100}</Data>""",
      """EventRecordID>({record_id}[^<]{1,2000})<""",
      """<Data Name=('|")SubjectUserSid('|")>({subject_sid}[^<]{1,2000})</Data>""",
      """<Data Name=('|")KeyLength('|")>({key_length}[^<]{1,2000})</Data>"""
    ]
    DupFields = ["process_directory->directory"]
  }
```