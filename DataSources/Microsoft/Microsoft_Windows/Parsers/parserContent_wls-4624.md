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
      """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
      """Computer="+({host}[^"]+)"""",
      """LogonType="+({logon_type}[^"]+)"""",
      """AuthenticationPackageName="+({auth_package}[^"]+)"""",
      """LogonProcessName="+({auth_process}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """TargetUserName="+({user}[^"]+)"""",
      """TargetLogonId="+({logon_id}[^"]+)"""",
      """TargetUserSid="+({user_sid}[^"]+)"""",
      """TargetDomainName="+({domain}[^"]+)"""",
      """IpAddress="+(?:-|({src_ip}[^"]+))""""
      """WorkstationName="+([A-Fa-f:\d.]+|({src_host_windows}[^"]+))"""",
      """ProcessName="(-|({process}[^"]+))""", 
    ]
    DupFields = ["host->dest_host"]
  }
```