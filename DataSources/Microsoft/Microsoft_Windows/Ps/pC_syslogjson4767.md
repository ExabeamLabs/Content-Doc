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
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[^"]{1,2000})""",
    """({event_code}4767)""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"SubjectUserName":"({user}[^"]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
    """"TargetDomainName":"({target_domain}[^"]{1,2000})""",
    """"TargetUserName":"({target_user}[^"]{1,2000})""",
    """"TargetSid":"({target_user_sid}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```