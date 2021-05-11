#### Parser Content
```Java
{
Name = s-4770-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4770"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4770", "Kerberos サービス チケットが更新されました。", "アカウント名:" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4770,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """(?!\d{1,100})({host}[\w\-.]+),([^,]*,)?Kerberos サービス チケットが更新されました。""",
      """({event_code}4770)""",
      """アカウント名:\s{1,100}({user}[^@]+).+?\s{1,100}""",
      """アカウント ドメイン:\s{1,100}({domain}.+?)\s{1,100}サービス情報:""",
      """サービス名:\s{1,100}({service_name}.+?)\s{1,100}サービス ID:""",
      """サービス名:\s{1,100}({dest_host}.+?\$)\s{1,100}サービス ID:""",
      """チケット オプション:\s{1,100}({ticket_options}.+?)\s{1,100}チケット暗号化の種類:""",
      """チケット暗号化の種類:\s{1,100}({ticket_encryption_type}[^\s]+)""",
      """クライアント アドレス:\s{1,100}(::[\w]+:)?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|::1)"""
      """クライアント アドレス:\s{1,100}(::[\w]+:)?({dest_ip}(?!::1)[a-fA-F:\d.]+)"""
    ]
    DupFields = [ "computer_name->host" ]
  }
```