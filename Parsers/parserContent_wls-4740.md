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
      """Computer="+({dest_host}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """SubjectUserName="+({caller_user}[^"]+)"""",
      """SubjectDomainName="+({caller_domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """TargetUserSid="+({user_sid}[^"]+)"""",
      """TargetDomainName="+({src_host}[^"]+)"""",
      """TargetUserName="+({user}[^"]+)""""
    ]
    DupFields=[ "caller_domain->domain" ]
  }
```