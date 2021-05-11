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
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4768,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """({host}(?!\d{1,100})[\w\-.]+),([^,]*,)?Kerberos 認証チケット \(TGT\) が要求されました。""",
      """({event_code}4768)""",
      """アカウント名:\s{1,100}({user}[^@]+?)(?:@([^\s]+))?\s{1,100}提供された領域名:""",
      """クライアント アドレス:\s{1,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """結果コード:\s{1,100}({result_code}[\w]+)""",
      """提供された領域名:\s{1,100}({domain}[^\s]+)""",
      """ユーザー ID:\s{1,100}(?:NULL SID|({user_sid}.+?))\s{1,100}サービス情報:"""]
    DupFields = [ "computer_name->host" ]
  }
```