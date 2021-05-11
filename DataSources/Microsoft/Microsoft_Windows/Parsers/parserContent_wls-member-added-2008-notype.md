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
    """Computer="{1,20}({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
    """EventID="{1,20}({event_code}[^"]+)"""",
    """EventRecordID="{1,20}({record_id}[^"]+)"""",
    """SubjectUserName="{1,20}({user}[^"]+)"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]+)"""",
    """SubjectDomainName="{1,20}({domain}[^"]+)"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
    """TargetUserName="{1,20}({group_name}[^"]+)"""",
    """TargetDomainName="{1,20}({group_domain}[^"]+)"""",
    """MemberSid="{1,20}({account_id}[^"]+)"""",
    """MemberName="{1,20}({account_dn}[^"]+)"""",
    """MemberName="{1,20}.*?OU=({account_ou}[^,]+)?""",
    """TargetSid="({group_id}[^"]+)""",
  ]
  DupFields = [ "event_code->group_type", "host->dest_host" ]
}
```