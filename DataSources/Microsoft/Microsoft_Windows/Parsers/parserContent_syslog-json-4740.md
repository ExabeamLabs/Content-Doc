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
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[\w\-.]{1,2000})""",
    """({event_code}4740)""",
    """"SubjectUserName":"({caller_user}[^"]{1,2000})""",
    """"SubjectDomainName":"({caller_domain}[^"]{1,2000})""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
    """"TargetSid":"({user_sid}[^"]{1,2000})""",
    """"TargetUserName":"({user}[^"]{1,2000})""",
    """Additional Information:[rnt\\]{0,2000}Caller Computer Name:[rnt\\]{0,2000}({src_host}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host","caller_domain->domain" ]
}
```