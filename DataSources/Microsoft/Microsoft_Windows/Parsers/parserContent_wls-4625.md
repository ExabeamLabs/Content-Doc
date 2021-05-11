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
      """Computer="{1,20}({host}[^"]+)"""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """IpAddress="{1,20}(?:-|({src_ip}[^"]+))"""",
      """LogonProcessName="{1,20}({auth_process}[^"]+)"""",
      """LogonType="{1,20}({logon_type}[^"]+)"""",
      """AuthenticationPackageName="{1,20}({auth_package}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """SubStatus="{1,20}({result_code}[^"]+)"""",
      """SubjectUserName="{1,20}(?=\w)({caller_user}[^"]+)"""",
      """SubjectDomainName="{1,20}(?=\w)({caller_domain}[^"]+)"""",
      """TargetDomainName="(?:-|({domain}[^"]+))""",
      """TargetUserName="{1,20}(?=\w)({user}[^"@]+)(?:@({domain}[^\s]+))?"""",
      """TargetUserSid="{1,20}({user_sid}[^"]+)"""",
      """WorkstationName="{1,20}(-|({src_host_windows}[^"]+))"""",
      """FailureReason="{1,20}({failure_reason}[^"]+)"""",
    ]
    DupFields = ["host->dest_host"]
  }
```