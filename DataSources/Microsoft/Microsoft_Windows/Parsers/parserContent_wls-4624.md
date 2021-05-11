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
      """Computer="{1,20}({host}[^"]+)"""",
      """LogonType="{1,20}({logon_type}[^"]+)"""",
      """AuthenticationPackageName="{1,20}({auth_package}[^"]+)"""",
      """LogonProcessName="{1,20}({auth_process}[^"]+)"""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """TargetUserName="{1,20}({user}[^"]+)"""",
      """TargetLogonId="{1,20}({logon_id}[^"]+)"""",
      """TargetUserSid="{1,20}({user_sid}[^"]+)"""",
      """TargetDomainName="{1,20}({domain}[^"]+)"""",
      """IpAddress="{1,20}(?:-|({src_ip}[^"]+))""""
      """WorkstationName="{1,20}([A-Fa-f:\d.]+|({src_host_windows}[^"]+))"""",
      """ProcessName="(-|({process}[^"]+))""", 
      """KeyLength="{1,20}({key_length}[^"]+)"""",
      """SubjectUserSid="{1,20}({subject_sid}[^"]+)"""",
    ]
    DupFields = ["host->dest_host"]
  }
```