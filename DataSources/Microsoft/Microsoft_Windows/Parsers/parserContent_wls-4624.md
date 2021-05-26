#### Parser Content
```Java
{
Name = wls-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4624""""]
    Fields = [
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """Computer="{1,20}({host}[^"]{1,2000})"""",
      """LogonType="{1,20}({logon_type}[^"]{1,2000})"""",
      """AuthenticationPackageName="{1,20}({auth_package}[^"]{1,2000})"""",
      """LogonProcessName="{1,20}({auth_process}[^"]{1,2000})"""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """TargetUserName="{1,20}({user}[^"]{1,2000})"""",
      """TargetLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
      """TargetUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
      """TargetDomainName="{1,20}({domain}[^"]{1,2000})"""",
      """IpAddress="{1,20}(?:-|({src_ip}[^"]{1,2000}))""""
      """WorkstationName="{1,20}([A-Fa-f:\d.]{1,2000}|({src_host_windows}[^"]{1,2000}))"""",
      """ProcessName="(-|({process}[^"]{1,2000}))""", 
      """KeyLength="{1,20}({key_length}[^"]{1,2000})"""",
      """SubjectUserSid="{1,20}({subject_sid}[^"]{1,2000})"""",
    ]
    DupFields = ["host->dest_host"]
  }
```