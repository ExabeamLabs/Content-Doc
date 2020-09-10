#### Parser Content
```Java
{
Name = syslog-json-4767
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-unlocked"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """"EventID":4767""", """A user account was unlocked.""", """"Category"""" ]
  Fields = [
    """({event_name}A user account was unlocked)""",
    """"EventTime":\s*"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[^"]+)""",
    """({event_code}4767)""",
    """"SubjectUserSid":"({user_sid}[^"]+)""",
    """"SubjectUserName":"({user}[^"]+)""",
    """"SubjectDomainName":"({domain}[^"]+)""",
    """"SubjectLogonId":"({logon_id}[^"]+)""",
    """"TargetDomainName":"({target_domain}[^"]+)""",
    """"TargetUserName":"({target_user}[^"]+)""",
    """"TargetSid":"({target_user_sid}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```