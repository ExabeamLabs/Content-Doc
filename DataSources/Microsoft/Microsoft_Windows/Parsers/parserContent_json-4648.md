#### Parser Content
```Java
{
Name = json-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""4648""", """"TargetServerName":"""]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
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
      """"(?i)(ProcessId)":"*({process_id}[^",]*)""",
      """"ProcessName":"(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))"""",
      """"IpAddress":"(?:-|({src_ip}[^"]*))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```