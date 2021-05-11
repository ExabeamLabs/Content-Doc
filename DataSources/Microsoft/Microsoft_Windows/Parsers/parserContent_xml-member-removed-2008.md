#### Parser Content
```Java
{
Name = xml-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-removed"
  TimeFormat = "yyyy-MM-DD'T'HH:mm:ss.SSS"
  Conditions = [ "Security ID:", "Logon ID:", "A member was removed from a security-enabled", "<EventID>"]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)\d{1,100}Z'""",
    """exabeam_host=({host}[\w\-.]+)""",
    """<Computer>({host}[^<]+)""",
    """<EventID>({event_code}[^<]+)""",
    """A member was removed from a security-enabled\s{0,100}({group_type}[^\s]+)\s{1,100}group""",
    """'MemberName'>(-|({account_id}[^<]+))<""",
    """'MemberSid'>({sid_user}[^<]+)""",
    """'SubjectUserSid'>({user_sid}[^"\s<]+)<""",
    """'SubjectUserName'>({user}[^"\s<]+)<""",
    """'SubjectDomainName'>({domain}[^"\s<]+)<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]+)<""",
    """CN=({account_id}.*?(?=,OU))""",
    """OU=({account_ou}[^,]+)""",
    """DC=({account_dn}[^,<]+)"""
    """'TargetUserName'>({group_name}[^<]+)""",
    """'TargetDomainName'>({group_domain}[^<]+)""",
    """'TargetSid'>({group_id}[^<]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```