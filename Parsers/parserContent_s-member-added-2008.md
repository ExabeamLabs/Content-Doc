#### Parser Content
```Java
{
Name = s-member-added-2008-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-member-added"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ """exabeam_raw""", "EventCode=", "セキュリティが有効な" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """ComputerName=({host}[\w.\-]+)""",
      """EventCode=({event_code}[\w]+)""",
      """セキュリティが有効な({group_type}[^\s]+) グループにメンバーが追加されました。""",
      """サブジェクト:.+?アカウント名:\s+({user}[^\s]+)""",
      """アカウント ドメイン:\s+({user_domain}[^\s]+)""",
      """ログオン ID:\s+({logon_id}[^\s]+)\s+""",
      """メンバー:\s+セキュリティ ID:\s+({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s+アカウント名:""",
      """メンバー:.+?アカウント名:\s*({account_dn}.+?)\s*グループ:""",
      """グループ:\s+セキュリティ ID:\s+({group_id}[^\s]+)""",
      """グループ:.+?グループ名:\s+({group_name}.+?)?\s+グループ ドメイン:""",
      """グループ:.+?グループ ドメイン:\s+({group_domain}[^\s]+)"""]
    DupFields = [ "host->computer_name" ]
  }
```