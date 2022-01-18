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
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000})<\/Data>""",
      """<Data Name(\\)?='SubjectUserName'>(-|({user}[^<]{1,2000}))</Data>""",
      """<Data Name(\\)?='SubjectDomainName'>(-|({domain}[^<]{1,2000}))</Data>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetUserName'>({account}[^<]{1,2000}?)\s{0,100}</Data>""",
      """<Data Name(\\)?='TargetDomainName'>({account_domain}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetServerName'>({dest_host}[\w\-]{1,2000})[^<]{0,2000}</Data>""",
      """<Data Name(\\)?='ProcessId'>({process_id}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='ProcessName'>({process}({directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))<\/Data>""",
      """<Data Name(\\)?='IpAddress'>({src_ip}[a-fA-F:\d.]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetInfo'>({dest_service}[^<]{1,2000})</Data>"""
    ]
    DupFields = ["directory->process_directory"]
  

}
```