#### Parser Content
```Java
{
Name = wls-4723
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4723"""" ]
    Fields = [
      """Computer="+({host}[^"]+)"""",
      """({time}\w+ \d+ \d\d:\d\d:\d\d)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Keywords="+({outcome}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """SubjectUserName="+({user}[^"]+)"""",
      """SubjectDomainName="+({domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """SubjectUserSid="+({user_sid}[^"]+)"""",
      """TargetSid="+({target_user_sid}[^"]+)"""",
      """TargetDomainName="+({target_domain}[^"]+)"""",
      """TargetUserName="+({target_user}[^"]+)""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```