#### Parser Content
```Java
{
Name = s-4770-jp
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-4770"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4770", "Kerberos サービス チケットが更新されました。", "アカウント名:" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4770,""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000},)?Kerberos サービス チケットが更新されました。""",
      """({event_code}4770)""",
      """アカウント名:\s{1,100}({user}[^@]{1,2000}).+?\s{1,100}""",
      """アカウント ドメイン:\s{1,100}({domain}.+?)\s{1,100}サービス情報:""",
      """サービス名:\s{1,100}({service_name}.+?)\s{1,100}サービス ID:""",
      """サービス名:\s{1,100}({dest_host}.+?\$)\s{1,100}サービス ID:""",
      """チケット オプション:\s{1,100}({ticket_options}.+?)\s{1,100}チケット暗号化の種類:""",
      """チケット暗号化の種類:\s{1,100}({ticket_encryption_type}[^\s]{1,2000})""",
      """クライアント アドレス:\s{1,100}(::[\w]{1,2000}:)?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|::1)"""
      """クライアント アドレス:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}(?!::1)[a-fA-F:\d.]{1,2000})"""
    ]
    DupFields = [ "computer_name->host" ]
  }
```