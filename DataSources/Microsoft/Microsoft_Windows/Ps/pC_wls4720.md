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
    """Computer="{1,20}({host}[^"]{1,2000})"""",
    """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
    """EventID="{1,20}({event_code}[^"]{1,2000})"""",
    """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
    """SubjectUserName ="{1,20}({user}[^"]{1,2000})"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
    """SubjectDomainName ="{1,20}({domain}[^"]{1,2000})"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
    """TargetUserName ="{1,20}({account_name}[^"]{1,2000})"""",
    """TargetDomainName ="{1,20}({account_domain}[^"]{1,2000})"""",
    """TargetSid="{1,20}({account_id}[^"]{1,2000})"""",
    """Enabled.*?'({user_type}[^']{1,2000})"""
  ]
  DupFields = ["host->dest_host"]


}
```