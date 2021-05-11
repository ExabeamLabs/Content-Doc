#### Parser Content
```Java
{
Name = wls-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LogType="WLS"""", """EventID="4771"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Computer="{1,20}({dest_host}[^"]+)"""",
    """EventID="{1,20}({event_code}[^"]+)"""",
    """EventRecordID="{1,20}({record_id}[^"]+)"""",
    """IpAddress="{1,20}(?:::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""",
    """ServiceName="{1,20}\w+\/(?=\w)({domain}[^"]+)"""",
    """Status="{1,20}({result_code}[^"]+)"""",
    """TargetSid="{1,20}({user_sid}[^"]+)"""",
    """TargetUserName="{1,20}(?=\w)({user}[^"]+)""""
  ]
}
```