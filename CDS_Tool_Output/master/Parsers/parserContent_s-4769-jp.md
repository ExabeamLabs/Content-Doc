#### Parser Content
```Java
{
Name = s-4769-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4769"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4769", "Kerberos サービス チケットが要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4769,""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?Kerberos サービス チケットが要求されました。""",
      """({event_code}4769)""",
      """アカウント名:\s+({user}[^@]+)@({domain}[\w._\-]+)""",
      """サービス名:\s+({dest_host}\S+\$)\s+サービス ID:""",
      """サービス名:\s+({service_name}\S+)\s+サービス ID:""",
      """チケット オプション:\s+({ticket_options}\S+)\s+チケット暗号化の種類:""",
      """チケット暗号化の種類:\s+({ticket_encryption_type}\S+)\s+エラー コード:""",
      """クライアント アドレス:\s+(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """エラー コード:\s+({result_code}[\w]+)""" ]
    DupFields = [ "computer_name->host" ]
  }
```