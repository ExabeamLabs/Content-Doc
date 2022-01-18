#### Parser Content
```Java
{
Name = windows-xml-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>47""", """>A member was added to a security-enabled""", """<Provider Name =""" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """<TimeCreated SystemTime='({time}\d{1,200}-\d{1,100}-\d{1,200}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """A member was added to a security-enabled ({group_type}[^\s]{1,2000}) group""",
    """<Data Name ='SubjectUserSid'>({user_sid}[^<]{1,2000})<"""
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<""",
    """<Data Name ='MemberSid'>({account_id}[^<]{1,2000})<""",
    """<Data Name ='TargetDomainName'>({group_domain}[^<]{1,2000})<""",
    """<Data Name ='TargetSid'>({group_id}[^<]{1,2000})<"""
    """<Data Name ='TargetUserName'>({group_name}[^<]{1,2000})<""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))|(?:.+?))\s{0,100}Group:"""
  ]
  DupFields = [ "host->dest_host" ]


}
```