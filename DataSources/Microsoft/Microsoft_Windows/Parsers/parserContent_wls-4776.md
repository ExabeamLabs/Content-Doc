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
      """Computer="{1,20}({host}[^"]+)"""",
      """\sWorkstation="{1,20}({dest_host}[^".,]+)""",
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """Computer="{1,20}(?!(?:[A-Fa-f:\d.]+))[^".]+\.({domain}[^".]+)""",
      """TargetUserName="{1,20}({user}[^"@]+)(?:@({domain}[^".]+)[^"]*)?"""",
      """Status="{1,20}({result_code}[^"]+)"""",
    ]
  }
```