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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Computer="{1,20}({dest_host}[^"]{1,2000})"""",
    """EventID="{1,20}({event_code}[^"]{1,2000})"""",
    """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
    """IpAddress="{1,20}(?:::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})"""",
    """ServiceName ="{1,20}\w+\/(?=\w)({domain}[^"]{1,2000})"""",
    """Status="{1,20}({result_code}[^"]{1,2000})"""",
    """TargetSid="{1,20}({user_sid}[^"]{1,2000})"""",
    """TargetUserName ="{1,20}(?=\w)({user}[^"]{1,2000})""""
  ]


}
```