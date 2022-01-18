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
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[^."]{0,2000})""",
    """"EventID":({event_code}[^,]{1,2000})""",
    """"RecordNumber":({record_id}[^,]{1,2000})""",
    """"Message":"A member was added to a security-enabled ({group_type}[^\s]{1,2000}) group.""",
    """"SubjectUserName":"({user}[^"]{1,2000})""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
    """"TargetUserName":"({group_name}[^"]{1,2000})""",
    """"TargetDomainName":"({group_domain}[^"]{1,2000})""",
    """"MemberSid":"({account_id}[^"]{1,2000})""",
    """"MemberName":"({account_dn}[^"]{1,2000})""",
    """"MemberName":"CN=.*,({account_ou}OU=.+?DC=.+?[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]


}
```