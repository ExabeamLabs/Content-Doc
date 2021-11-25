#### Parser Content
```Java
{
Name = xml-4625
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4625</EventID>""", """'FailureReason'>"""]
    Fields = [
      """TimeCreated SystemTime(\\)?='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
      """<Computer>({host}({dest_host}[\w\-]{1,2000})[^<]{0,2000})</Computer>""",
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Data Name(\\)?='SubjectUserName'>(?=\w)?(-|({caller_user}[^<]{1,2000}))<\/Data>""",
      """<Data Name(\\)?='SubjectDomainName'>((?=\w))?(-|({caller_domain}[^<]{1,2000}))<\/Data>""",
      """<Data Name(\\)?='LogonType'>({logon_type}\d{1,100})<\/Data>""",
      """<Data Name(\\)?='TargetUserSid'>({user_sid}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetUserName'>(?=\w)(({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^<]{1,2000})|({user}[^<]{1,2000}))<\/Data>""",
      """<Data Name(\\)?='TargetDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='Status'>({result_code}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='SubStatus'>({result_code}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='IpAddress'>(?:-|({src_ip}[A-Fa-f\d.:]{1,2000}))</Data>""",
      """<Data Name(\\)?='LogonProcessName'>({auth_process}[^\s<]{1,2000})""",
      """<Data Name(\\)?='WorkstationName'>(-|({src_host_windows}[A-Za-z]{1,2000}[\w.-]{1,2000}))\s{0,100}</Data>""",
      """<Data Name(\\)?='AuthenticationPackageName'>({auth_package}[^<]{1,2000})</Data>""",
      """({event_name}An account failed to log on)""",
      """<Data Name(\\)?='FailureReason'>({failure_reason}[^<]{1,2000})</Data>"""
      """<Data Name =('|")SubjectUserSid('|")>({subject_sid}[^<]{1,2000})</Data>""",
      """<Data Name =('|")KeyLength('|")>({key_length}[^<]{1,2000})</Data>"""
    ]
    DupFields = ["src_host_windows->src_host"]
  

}
```