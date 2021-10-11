#### Parser Content
```Java
{
Name = s-4768-jp
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-4768"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4768", "Kerberos 認証チケット (TGT) が要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4768,""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """({host}(?!\d{1,100})[\w\-.]{1,2000}),([^,]{0,2000},)?Kerberos 認証チケット \(TGT\) が要求されました。""",
      """({event_code}4768)""",
      """アカウント名:\s{1,100}({user}[^@]{1,2000}?)(?:@([^\s]{1,2000}))?\s{1,100}提供された領域名:""",
      """クライアント アドレス:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """結果コード:\s{1,100}({result_code}[\w]{1,2000})""",
      """提供された領域名:\s{1,100}({domain}[^\s]{1,2000})""",
      """ユーザー ID:\s{1,100}(?:NULL SID|({user_sid}.+?))\s{1,100}サービス情報:"""]
    DupFields = [ "computer_name->host" ]
  }
```