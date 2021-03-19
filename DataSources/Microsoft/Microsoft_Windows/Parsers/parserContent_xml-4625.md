#### Parser Content
```Java
{
Name = xml-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4625</EventID>""", """'FailureReason'>"""]
    Fields = [
      """TimeCreated SystemTime(\\)?='({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
      """<Computer>({host}({dest_host}[\w\-]+)[^<]*)</Computer>""",
      """<EventID>({event_code}\d+)</EventID>""",
      """<Data Name(\\)?='SubjectUserName'>(?=\w)?(-|({caller_user}[^<]+))<\/Data>""",
      """<Data Name(\\)?='SubjectDomainName'>((?=\w))?(-|({caller_domain}[^<]+))<\/Data>""",
      """<Data Name(\\)?='LogonType'>({logon_type}\d+)<\/Data>""",
      """<Data Name(\\)?='TargetUserSid'>({user_sid}[^<]+)</Data>""",
      """<Data Name(\\)?='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
      """<Data Name(\\)?='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
      """<Data Name(\\)?='SubStatus'>({result_code}[^<]+)</Data>""",
      """<Data Name(\\)?='Status'>({result_code}[^<]+)</Data>""",
      """<Data Name(\\)?='IpAddress'>(?:-|({src_ip}[A-Fa-f\d.:]+))</Data>""",
      """<Data Name(\\)?='LogonProcessName'>({auth_process}[^\s<]+)""",
      """<Data Name(\\)?='WorkstationName'>(-|({src_host_windows}[A-Za-z]+[\w.-]+))\s*</Data>""",
      """<Data Name(\\)?='AuthenticationPackageName'>({auth_package}[^<]+)</Data>""",
      """({event_name}An account failed to log on)""",
      """<Data Name(\\)?='FailureReason'>({failure_reason}[^<]+)</Data>"""
    ]
    DupFields = ["src_host_windows->src_host"]
  }
```