#### Parser Content
```Java
{
Name = xml-member-removed-2008
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "windows-member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ "Security ID:", "Logon ID:", "A member was removed from a security-enabled", "<EventID>"]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]{1,2000} group)""",
    """SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)\d{1,100}Z'""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """<Computer>({host}[^<]{1,2000})""",
    """<EventID>({event_code}[^<]{1,2000})""",
    """A member was removed from a security-enabled\s{0,100}({group_type}[^\s]{1,2000})\s{1,100}group""",
    """'MemberName'>(-|({account_id}[^<]{1,2000}))<""",
    """'MemberSid'>({sid_user}[^<]{1,2000})""",
    """'SubjectUserSid'>({user_sid}[^"\s<]{1,2000})<""",
    """'SubjectUserName'>({user}[^"\s<]{1,2000})<""",
    """'SubjectDomainName'>({domain}[^"\s<]{1,2000})<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]{1,2000})<""",
    """CN=({account_id}.*?(?=,OU))""",
    """OU=({account_ou}[^,]{1,2000})""",
    """DC=({account_dn}[^,<]{1,2000})"""
    """'TargetUserName'>({group_name}[^<]{1,2000})""",
    """'TargetDomainName'>({group_domain}[^<]{1,2000})""",
    """'TargetSid'>({group_id}[^<]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```