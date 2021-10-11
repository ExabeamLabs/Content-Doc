#### Parser Content
```Java
{
Name = s-4769-jp
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-4769"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4769", "Kerberos サービス チケットが要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4769,""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000},)?Kerberos サービス チケットが要求されました。""",
      """({event_code}4769)""",
      """アカウント名:\s{1,100}({user}[^@]{1,2000})@({domain}[\w._\-]{1,2000})""",
      """サービス名:\s{1,100}({dest_host}\S+\$)\s{1,100}サービス ID:""",
      """サービス名:\s{1,100}({service_name}\S+)\s{1,100}サービス ID:""",
      """チケット オプション:\s{1,100}({ticket_options}\S+)\s{1,100}チケット暗号化の種類:""",
      """チケット暗号化の種類:\s{1,100}({ticket_encryption_type}\S+)\s{1,100}エラー コード:""",
      """クライアント アドレス:\s{1,100}(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
      """エラー コード:\s{1,100}({result_code}[\w]{1,2000})""" ]
    DupFields = [ "computer_name->host" ]
  }
```