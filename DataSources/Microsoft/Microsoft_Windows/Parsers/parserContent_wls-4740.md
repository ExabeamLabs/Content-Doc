#### Parser Content
```Java
{
Name = wls-4740
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-lockout"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4740"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="{1,20}({dest_host}[^"]+)"""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """SubjectUserName="{1,20}({caller_user}[^"]+)"""",
      """SubjectDomainName="{1,20}({caller_domain}[^"]+)"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
      """TargetUserSid="{1,20}({user_sid}[^"]+)"""",
      """TargetDomainName="{1,20}({src_host}[^"]+)"""",
      """TargetUserName="{1,20}({user}[^"]+)""""
    ]
    DupFields=[ "caller_domain->domain" ]
  }
```