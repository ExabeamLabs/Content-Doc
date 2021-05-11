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
    """Computer="{1,20}({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
    """EventID="{1,20}({event_code}[^"]+)"""",
    """EventRecordID="{1,20}({record_id}[^"]+)"""",
    """SubjectUserName="{1,20}({user}[^"]+)"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]+)"""",
    """SubjectDomainName="{1,20}({domain}[^"]+)"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
    """TargetUserName="{1,20}({account_name}[^"]+)"""",
    """TargetDomainName="{1,20}({account_domain}[^"]+)"""",
    """TargetSid="{1,20}({account_id}[^"]+)"""",
    """Enabled.*?'({user_type}[^']+)"""
  ]
  DupFields = ["host->dest_host"]
}
```