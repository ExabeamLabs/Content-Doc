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
      """Computer="{1,20}({host}[^"]{1,2000})"""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Keywords="{1,20}({outcome}[^"]{1,2000})"""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """SubjectUserName="{1,20}({user}[^"]{1,2000})"""",
      """SubjectDomainName="{1,20}({domain}[^"]{1,2000})"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
      """SubjectUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
      """TargetSid="{1,20}({target_user_sid}[^"]{1,2000})"""",
      """TargetDomainName="{1,20}({target_domain}[^"]{1,2000})"""",
      """TargetUserName="{1,20}({target_user}[^"]{1,2000})""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```