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
    """"EventTime":({time}\d{1,100})""",
    """"Hostname":"({host}[\w.-]{1,2000}?)"""",
    """"EventID":({event_code}\d{1,100})""",
    """({event_name}A member was removed from a security-enabled ({group_type}[\w\s]{1,2000}) group)""",
    """"SubjectUserName":"({user}[^"]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"MemberSid":"({account_id}[^"]{1,2000})""",
    """"MemberName":"({account_dn}CN=[^"]{1,2000}?,({account_ou}OU=[^"]{1,2000}?DC=[\w-]{1,2000}?))"""",
    """"TargetUserName":"({group_name}[^"]{1,2000})""",
    """"TargetDomainName":"({group_domain}[^"]{1,2000})""",
    """"TargetSid":"({group_id}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```