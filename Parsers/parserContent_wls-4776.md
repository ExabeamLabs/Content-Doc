#### Parser Content
```Java
{
Name = wls-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4776""""]
    Fields = [
      """Computer="+({host}[^"]+)"""",
      """\sWorkstation="+({dest_host}[^".,]+)""",
      """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """Computer="+(?!(?:[A-Fa-f:\d.]+))[^".]+\.({domain}[^".]+)""",
      """TargetUserName="+({user}[^"@]+)(?:@({domain}[^".]+)[^"]*)?"""",
      """Status="+({result_code}[^"]+)"""",
    ]
  }
```