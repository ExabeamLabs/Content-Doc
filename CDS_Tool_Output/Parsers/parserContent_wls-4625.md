#### Parser Content
```Java
{
Name = wls-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4625""""]
    Fields = [
      """Computer="+({host}[^"]+)"""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """IpAddress="+(?:-|({src_ip}[^"]+))"""",
      """LogonProcessName="+({auth_process}[^"]+)"""",
      """LogonType="+({logon_type}[^"]+)"""",
      """AuthenticationPackageName="+({auth_package}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """SubStatus="+({result_code}[^"]+)"""",
      """SubjectUserName="+(?=\w)({caller_user}[^"]+)"""",
      """SubjectDomainName="+(?=\w)({caller_domain}[^"]+)"""",
      """TargetDomainName="(?:-|({domain}[^"]+))""",
      """TargetUserName="+(?=\w)({user}[^"@]+)(?:@({domain}[^\s]+))?"""",
      """TargetUserSid="+({user_sid}[^"]+)"""",
      """WorkstationName="+(-|({src_host_windows}[^"]+))"""",
      """FailureReason="+({failure_reason}[^"]+)"""",
    ]
    DupFields = ["host->dest_host"]
  }
```