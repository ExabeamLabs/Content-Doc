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
      """Computer="{1,20}({host}[^"]{1,2000})"""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """IpAddress="{1,20}(?:-|({src_ip}[^"]{1,2000}))"""",
      """LogonProcessName="{1,20}({auth_process}[^"]{1,2000})"""",
      """LogonType="{1,20}({logon_type}[^"]{1,2000})"""",
      """AuthenticationPackageName="{1,20}({auth_package}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """SubStatus="{1,20}({result_code}[^"]{1,2000})"""",
      """SubjectUserName="{1,20}(?=\w)({caller_user}[^"]{1,2000})"""",
      """SubjectDomainName="{1,20}(?=\w)({caller_domain}[^"]{1,2000})"""",
      """TargetDomainName="(?:-|({domain}[^"]{1,2000}))""",
      """TargetUserName="{1,20}(?=\w)({user}[^"@]{1,2000})(?:@({domain}[^\s]{1,2000}))?"""",
      """TargetUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
      """WorkstationName="{1,20}(-|({src_host_windows}[^"]{1,2000}))"""",
      """FailureReason="{1,20}({failure_reason}[^"]{1,2000})"""",
    ]
    DupFields = ["host->dest_host"]
  }
```