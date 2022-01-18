#### Parser Content
```Java
{
Name = syslog-json-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4723""",""""SourceModuleType":""" ]
  Fields = [        
    """({event_name}An attempt was made to change an account's password)""",
        """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
              """"Hostname":"({host}[^."]{0,2000})""",
        """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
        """"EventType":"({outcome}[^"]{1,2000})""",
              """({event_code}4723)""",
        """"SubjectUserName":"({user}[^"]{1,2000})""",
        """"SubjectDomainName":"({domain}[^"]{1,2000})""",
        """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
        """"TargetSid":"({target_user_sid}[^"]{1,2000})""",
        """"TargetUserName":"({target_user}[^"]{1,2000})""",
        """"TargetDomainName":"({target_domain}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```