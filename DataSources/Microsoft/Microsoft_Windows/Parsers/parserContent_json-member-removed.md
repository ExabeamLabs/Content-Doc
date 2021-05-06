#### Parser Content
```Java
{
Name = json-member-removed
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-removed"
  TimeFormat = "epoch"
  Conditions = [ """"EventID":""", """A member was removed from a security-enabled""", """"MemberSid":""", """"MemberName":""" ]
  Fields = [
    """"EventTime":({time}\d+)""",
    """"Hostname":"({host}[\w.-]+?)"""",
    """"EventID":({event_code}\d+)""",
    """({event_name}A member was removed from a security-enabled ({group_type}[\w\s]+) group)""",
    """"SubjectUserName":"({user}[^"]+)""",
    """"SubjectDomainName":"({domain}[^"]+)"""",
    """"SubjectLogonId":"({logon_id}[^"]+)"""",
    """"SubjectUserSid":"({user_sid}[^"]+)""",
    """"MemberSid":"({account_id}[^"]+)""",
    """"MemberName":"({account_dn}CN=[^"]+?,({account_ou}OU=[^"]+?DC=[\w-]+?))"""",
    """"TargetUserName":"({group_name}[^"]+)""",
    """"TargetDomainName":"({group_domain}[^"]+)""",
    """"TargetSid":"({group_id}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```