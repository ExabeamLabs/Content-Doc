#### Parser Content
```Java
{
Name = syslog-json-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Message":"A member was added to a security-enabled """, """"SourceModuleType":""" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[^."]*)""",
    """"EventID":({event_code}[^,]+)""",
    """"RecordNumber":({record_id}[^,]+)""",
    """"Message":"A member was added to a security-enabled ({group_type}[^\s]+) group.""",
    """"SubjectUserName":"({user}[^"]+)""",
    """"SubjectUserSid":"({user_sid}[^"]+)""",
    """"SubjectDomainName":"({domain}[^"]+)""",
    """"SubjectLogonId":"({logon_id}[^"]+)""",
    """"TargetUserName":"({group_name}[^"]+)""",
    """"TargetDomainName":"({group_domain}[^"]+)""",
    """"MemberSid":"({account_id}[^"]+)""",
    """"MemberName":"({account_dn}[^"]+)""",
    """"MemberName":"CN=.*,({account_ou}OU=.+?DC=.+?[^"]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```