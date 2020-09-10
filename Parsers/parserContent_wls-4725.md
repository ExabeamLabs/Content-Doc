#### Parser Content
```Java
{
Name = wls-4725
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-disabled"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4725"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="+({dest_host}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """SubjectUserSid="+({user_sid}[^"]+)"""",
      """SubjectUserName="+({user}[^"]+)"""",
      """SubjectDomainName="+({domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """TargetSid="+({target_user_sid}[^"]+)"""",
      """TargetDomainName="+({target_domain}[^"]+)"""",
      """TargetUserName="+({target_user}[^"]+)""""
    ]
  }
```