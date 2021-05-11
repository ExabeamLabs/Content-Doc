#### Parser Content
```Java
{
Name = wls-4724
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-reset"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4724"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="{1,20}({dest_host}[^"]+)"""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """SubjectUserSid="{1,20}({user_sid}[^"]+)"""",
      """SubjectUserName="{1,20}({user}[^"]+)"""",
      """SubjectDomainName="{1,20}({domain}[^"]+)"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
      """TargetSid="{1,20}({target_user_sid}[^"]+)"""",
      """TargetDomainName="{1,20}({target_domain}[^"]+)"""",
      """TargetUserName="{1,20}({target_user}[^"]+)""""
    ]
  }
```