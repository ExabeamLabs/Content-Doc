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
      """Computer="{1,20}({host}[^"]+)"""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Keywords="{1,20}({outcome}[^"]+)"""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """SubjectUserName="{1,20}({user}[^"]+)"""",
      """SubjectDomainName="{1,20}({domain}[^"]+)"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
      """SubjectUserSid="{1,20}({user_sid}[^"]+)"""",
      """TargetSid="{1,20}({target_user_sid}[^"]+)"""",
      """TargetDomainName="{1,20}({target_domain}[^"]+)"""",
      """TargetUserName="{1,20}({target_user}[^"]+)""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```