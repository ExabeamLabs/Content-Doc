#### Parser Content
```Java
{
Name = wls-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="627"""" ]
    Fields = [
      """({event_name}Change Password Attempt)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """CallerDomain="+({domain}[^"]+)"""",
      """CallerLogonId="+\([^,]+,({logon_id}[^\)]+)"""",
      """CallerUserName="+({user}[^"]+)"""",
      """TargetAccountID="+\%\{({target_user_sid}[^}]+)\}"""",
      """TargetAccountName="+({target_user}[^"]+)"""",
      """TargetDomain="+({target_domain}[^"]+)""""
    ]
    DupFields=[ "host->dest_host" ]
  }
```