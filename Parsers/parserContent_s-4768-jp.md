#### Parser Content
```Java
{
Name = s-4768-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4768"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4768", "Kerberos 認証チケット (TGT) が要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4768,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """({host}(?!\d+)[\w\-.]+),([^,]*,)?Kerberos 認証チケット \(TGT\) が要求されました。""",
      """({event_code}4768)""",
      """アカウント名:\s+({user}[^@]+?)(?:@([^\s]+))?\s+提供された領域名:""",
      """クライアント アドレス:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """結果コード:\s+({result_code}[\w]+)""",
      """提供された領域名:\s+({domain}[^\s]+)""",
      """ユーザー ID:\s+(?:NULL SID|({user_sid}.+?))\s+サービス情報:"""]
    DupFields = [ "computer_name->host" ]
  }
```