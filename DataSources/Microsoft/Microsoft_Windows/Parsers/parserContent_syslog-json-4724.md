#### Parser Content
```Java
{
Name = syslog-json-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-reset"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4724""",""""SourceModuleType":""" ]
  Fields = [  
    """({event_name}An attempt was made to reset an account's password)""",
        """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
              """"Hostname":"({host}[^."]*)""",
              """({event_code}4724)""",
        """"SubjectUserSid":"({user_sid}[^"]+)""",
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