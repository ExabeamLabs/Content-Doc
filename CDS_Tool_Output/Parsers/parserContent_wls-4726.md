#### Parser Content
```Java
{
Name = wls-4726
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-deleted"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4726"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="+({dest_host}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """SubjectUserName="+({user}[^"]+)"""",
      """SubjectDomainName="+({domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """SubjectUserSid="+({user_sid}[^"]+)"""",
      """TargetDomainName="+({target_domain}[^"]+)"""",
      """TargetUserName="+({target_user}[^"]+)""""
      """TargetSid="+({target_user_sid}[^"]+)""""
    ]
    DupFields = [ "target_user->account_name" ]
  }
```