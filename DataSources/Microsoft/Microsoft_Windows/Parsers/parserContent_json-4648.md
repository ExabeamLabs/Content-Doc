#### Parser Content
```Java
{
Name = json-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["""4648""", """"TargetServerName":"""]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """"(Hostname|MachineName)":"({host}[^"]{0,2000})""",
      """({event_code}4648)""",
      """"SubjectUserSid":"({user_sid}[^"]{0,2000})""",
      """"SubjectUserName":"({user}[^"]{0,2000})""",
      """"SubjectDomainName":"({domain}[^"]{0,2000})""",
      """"SubjectLogonId":"({logon_id}[^"]{0,2000})""",
      """"TargetUserName":"({account}[^"]{0,2000})""",
      """"TargetDomainName":"({account_domain}[^\s"]{0,2000})""",
      """"TargetServerName":"({dest_host}[^"]{0,2000})""",
      """"TargetInfo":"({dest_service}[^"]{0,2000})""",
      """"(?i)(ProcessId)":"{0,20}({process_id}[^",]{0,2000})""",
      """"ProcessName":"(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))"""",
      """"IpAddress":"(?:-|({src_ip}[^"]{0,2000}))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```