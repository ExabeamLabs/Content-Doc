#### Parser Content
```Java
{
Name = wls-675
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-675"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="675"""" ]
    Fields = [
      """({event_name}Pre-authentication failed)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="+({dest_host}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """IpAddress="+(?:::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""",
      """ServiceName="+\w+\/(?=\w)({domain}[^"]+)"""",
      """Status="+({result_code}[^"]+)"""",
      """TargetSid="+({user_sid}[^"]+)"""",
      """TargetUserName="+(?=\w)({user}[^"]+)""""
    ]
  }
```