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
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """CallerDomain="+({caller_domain}[^"]+)"""",
      """CallerLogonId="+\([^,]+,({logon_id}[^\)]+)"""",
      """CallerUserName="+({caller_user}[^"]+)"""",
      """TargetAccountID="+\%\{({user_sid}[^}]+)\}"""",
      """TargetAccountName="+({user}[^"]+)""""
    ]
    DupFields=[ "host->dest_host",
      "caller_domain->domain"]
  }
```