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
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d\/\d\d\/\d\d[\s\t]+\d\d:\d\d:\d\d)\s{1,100}Microsoft-Windows-Security-Auditing""",
      """\s{1,100}ソース ワークステーション:\s{1,100}(\\+)?(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)({dest_host}[^\s]+)))\s{1,100}エラー コード:""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4776,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """\W4776\s{1,100}({host}[\w\-.]+)""",
      """(?!\d{1,100})({host}[\w\-.]+),([^,]*,)?コンピューターがアカウントの資格情報の確認を試行しました。""",
      """({event_code}4776)""",
      """ログオン アカウント:\s{1,100}({user}[^@]+?)(?:@({domain}[^\s]+))?\s{1,100}ソース ワークステーション:""",
      """エラー コード:\s{1,100}({result_code}[\w\-]+)""" ]
    DupFields = [ "computer_name->host" ]

  }
```