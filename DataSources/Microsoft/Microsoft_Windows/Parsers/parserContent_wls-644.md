#### Parser Content
```Java
{
Name = wls-644
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-lockout"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="644"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """CallerDomain="{1,20}({caller_domain}[^"]+)"""",
      """CallerLogonId="{1,20}\([^,]+,({logon_id}[^\)]+)"""",
      """CallerUserName="{1,20}({caller_user}[^"]+)"""",
      """TargetAccountID="{1,20}\%\{({user_sid}[^}]+)\}"""",
      """TargetAccountName="{1,20}({user}[^"]+)""""
      """CallerMachineName="{1,20}({src_host}[^"]+)"""",
    ]
    DupFields=[ "host->dest_host",
      "caller_domain->domain"]
  }
```