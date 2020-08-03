#### Parser Content
```Java
{
Name = wls-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LogType="WLS"""", """EventID="4720"""" ]
  Fields = [
    """Computer="+({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
    """EventID="+({event_code}[^"]+)"""",
    """EventRecordID="+({record_id}[^"]+)"""",
    """SubjectUserName="+({user}[^"]+)"""",
    """SubjectUserSid="+({user_sid}[^"]+)"""",
    """SubjectDomainName="+({domain}[^"]+)"""",
    """SubjectLogonId="+({logon_id}[^"]+)"""",
    """TargetUserName="+({account_name}[^"]+)"""",
    """TargetDomainName="+({account_domain}[^"]+)"""",
    """TargetSid="+({account_id}[^"]+)"""",
    """Enabled.*?'({user_type}[^']+)"""
  ]
  DupFields = ["host->dest_host"]
}
```