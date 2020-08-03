#### Parser Content
```Java
{
Name = wls-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4768""""]
    Fields = [
      """Computer="+({host}[^"]+)"""",
      """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """TargetUserName="+({user}[^"]+)"""",
      """TargetDomainName="+({domain}[^"]+)"""",
      """TargetSid="+({user_sid}[^"]+)"""",
      """IpAddress="+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Status="+({result_code}[^"]+)""""
    ]
    DupFields = ["host->dest_host"]
  }
```