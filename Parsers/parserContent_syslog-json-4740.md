#### Parser Content
```Java
{
Name = syslog-json-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":""", """4740""","""A user account was locked out""" ]
  Fields = [ 
    """({event_name}A user account was locked out)""",
    """"EventTime":\s*"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[\w\-.]+)""",
    """({event_code}4740)""",
    """"SubjectUserName":"({caller_user}[^"]+)""",
    """"SubjectDomainName":"({caller_domain}[^"]+)""",
    """"SubjectLogonId":"({logon_id}[^"]+)""",
    """"TargetSid":"({user_sid}[^"]+)""",
    """"TargetUserName":"({user}[^"]+)""",
    """Additional Information:[rnt\\]*Caller Computer Name:[rnt\\]*({src_host}[^"]+)"""
  ]
  DupFields = [ "host->dest_host","caller_domain->domain" ]
}
```