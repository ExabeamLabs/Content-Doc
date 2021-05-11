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
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """CallerDomain="{1,20}({domain}[^"]+)"""",
      """CallerLogonId="{1,20}\([^,]+,({logon_id}[^\)]+)"""",
      """CallerUserName="{1,20}({user}[^"]+)"""",
      """TargetAccountID="{1,20}\%\{({target_user_sid}[^}]+)\}"""",
      """TargetAccountName="{1,20}({target_user}[^"]+)"""",
      """TargetDomain="{1,20}({target_domain}[^"]+)""""
    ]
    DupFields=[ "host->dest_host" ]
  }
```