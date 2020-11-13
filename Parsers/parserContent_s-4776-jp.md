#### Parser Content
```Java
{
Name = s-4776-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4776"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4776", "コンピューターがアカウントの資格情報の確認を試行しました。"]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d\/\d\d\/\d\d[\s\t]+\d\d:\d\d:\d\d)\s+Microsoft-Windows-Security-Auditing""",
      """\s+ソース ワークステーション:\s+(\\+)?(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)({dest_host}[^\s]+)))\s+エラー コード:""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4776,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """\W4776\s+({host}[\w\-.]+)""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?コンピューターがアカウントの資格情報の確認を試行しました。""",
      """({event_code}4776)""",
      """ログオン アカウント:\s+({user}[^@]+?)(?:@({domain}[^\s]+))?\s+ソース ワークステーション:""",
      """エラー コード:\s+({result_code}[\w\-]+)""" ]
    DupFields = [ "computer_name->host" ]

  }
```