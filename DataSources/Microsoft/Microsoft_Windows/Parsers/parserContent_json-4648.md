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
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4648)""",
      """"SubjectUserSid":"({user_sid}[^"]*)""",
      """"SubjectUserName":"({user}[^"]*)""",
      """"SubjectDomainName":"({domain}[^"]*)""",
      """"SubjectLogonId":"({logon_id}[^"]*)""",
      """"TargetUserName":"({account}[^"]*)""",
      """"TargetDomainName":"({account_domain}[^\s"]*)""",
      """"TargetServerName":"({dest_host}[^"]*)""",
      """"TargetInfo":"({dest_service}[^"]*)""",
      """"(?i)(ProcessId)":"{0,20}({process_id}[^",]*)""",
      """"ProcessName":"(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))"""",
      """"IpAddress":"(?:-|({src_ip}[^"]*))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```