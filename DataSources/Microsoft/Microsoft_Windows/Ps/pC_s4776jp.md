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
      """({time}\d\d\d\d\/\d\d\/\d\d[\s\t]{1,2000}\d\d:\d\d:\d\d)\s{1,100}Microsoft-Windows-Security-Auditing""",
      """\s{1,100}ソース ワークステーション:\s{1,100}(\\+)?(({dest_ip}[A-Fa-f:\d.]{1,2000})|(?:(?!NULL)({dest_host}[^\s]{1,2000})))\s{1,100}エラー コード:""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4776,""",
      """ComputerName =({computer_name}[\w.\-]{1,2000})""",
      """\W4776\s{1,100}({host}[\w\-.]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000

}
```