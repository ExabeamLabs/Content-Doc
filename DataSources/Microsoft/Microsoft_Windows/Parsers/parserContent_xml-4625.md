#### Parser Content
```Java
{
Name = xml-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4625</EventID>", "<Data Name='FailureReason'>"]
    Fields = [
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Data Name='SubjectUserName'>(?=\w)({caller_user}[^<]+)</Data>""",
      """<Data Name='SubjectDomainName'>(?=\w)({caller_domain}[^<]+)</Data>""",
      """<Data Name='LogonType'>({logon_type}\d+)</Data>""",
      """<Data Name='TargetUserSid'>({user_sid}[^<]+)</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
      """<Data Name='SubStatus'>({result_code}[^<]+)</Data>""",
      """<Data Name='IpAddress'>(?:-|({src_ip}[^<]+))</Data>""",
      """<Data Name='LogonProcessName'>({auth_process}[^\s<]+)""",
      """<Data Name='WorkstationName'>(-|({src_host_windows}[^\s<]+))""",
      """<Data Name='AuthenticationPackageName'>({auth_package}[^<]+)</Data>"""
    ]
    DupFields = ["host->dest_host", "src_host_windows->src_host"]
  }
```