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
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4770,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?Kerberos サービス チケットが更新されました。""",
      """({event_code}4770)""",
      """アカウント名:\s+({user}[^@]+).+?\s+""",
      """アカウント ドメイン:\s+({domain}.+?)\s+サービス情報:""",
      """サービス名:\s+({service_name}.+?)\s+サービス ID:""",
      """サービス名:\s+({dest_host}.+?\$)\s+サービス ID:""",
      """チケット オプション:\s+({ticket_options}.+?)\s+チケット暗号化の種類:""",
      """チケット暗号化の種類:\s+({ticket_encryption_type}[^\s]+)""",
      """クライアント アドレス:\s+(::[\w]+:)?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|::1)"""
      """クライアント アドレス:\s+(::[\w]+:)?({dest_ip}(?!::1)[a-fA-F:\d.]+)"""
    ]
    DupFields = [ "computer_name->host" ]
  }
```