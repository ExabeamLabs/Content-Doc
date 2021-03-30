#### Parser Content
```Java
{
Name = s-xml-windows-member-6
  DataType = "windows-member-removed"
  Conditions = [ "4757", "<Data Name='TargetSid'>", """A member was removed from a security-enabled universal group""" ]
  Fields = ${WinParserTemplates.s-xml-windows-member.Fields} [
    """"EventID":"({event_code}\d+)"""
  ]
}
s-xml-windows-member = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Data Name='MemberName'>({account_dn}(?i)(cn)=.+?,({account_ou}OU.+?DC=[\w-]+))</Data>""",
    """<Data Name='MemberSid'>({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s\<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({group_name}[^<]+)</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({group_domain}[^<]+)</Data>""",
    """<Data Name='TargetSid'>({group_id}[^<]+)</Data>""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
  ]

```