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
              """"Hostname":"({host}[^."]*)""",
        """"SubjectUserSid":"({user_sid}[^"]+)""",
        """"EventType":"({outcome}[^"]+)""",
              """({event_code}4723)""",
        """"SubjectUserName":"({user}[^"]+)""",
        """"SubjectDomainName":"({domain}[^"]+)""",
        """"SubjectLogonId":"({logon_id}[^"]+)""",
        """"TargetSid":"({target_user_sid}[^"]+)""",
        """"TargetUserName":"({target_user}[^"]+)""",
        """"TargetDomainName":"({target_domain}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```