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
      """Computer="{1,20}({host}[^"]{1,2000})"""",
      """\sWorkstation="{1,20}({dest_host}[^".,]{1,2000})""",
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """Computer="{1,20}(?!(?:[A-Fa-f:\d.]{1,2000}))[^".]{1,2000}\.({domain}[^".]{1,2000})""",
      """TargetUserName ="{1,20}({user}[^"@]{1,2000})(?:@({domain}[^".]{1,2000})[^"]{0,2000})?"""",
      """Status="{1,20}({result_code}[^"]{1,2000})"""",
    ]
  

}
```