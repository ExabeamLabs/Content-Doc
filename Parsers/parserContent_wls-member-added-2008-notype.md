#### Parser Content
```Java
{
Name = wls-member-added-2008-notype
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LogType="WLS"""", """MemberName=""", """MemberSid=""" ]
  Fields = [
    """Computer="+({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
    """EventID="+({event_code}[^"]+)"""",
    """EventRecordID="+({record_id}[^"]+)"""",
    """SubjectUserName="+({user}[^"]+)"""",
    """SubjectUserSid="+({user_sid}[^"]+)"""",
    """SubjectDomainName="+({domain}[^"]+)"""",
    """SubjectLogonId="+({logon_id}[^"]+)"""",
    """TargetUserName="+({group_name}[^"]+)"""",
    """TargetDomainName="+({group_domain}[^"]+)"""",
    """MemberSid="+({account_id}[^"]+)"""",
    """MemberName="+({account_dn}[^"]+)"""",
    """MemberName="+.*?OU=({account_ou}[^,]+)?""",
    """TargetSid="({group_id}[^"]+)""",
  ]
  DupFields = [ "event_code->group_type", "host->dest_host" ]
}
```