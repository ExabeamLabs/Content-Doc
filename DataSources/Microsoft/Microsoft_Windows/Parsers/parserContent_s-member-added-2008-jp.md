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
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """ComputerName=({host}[\w.\-]+)""",
      """EventCode=({event_code}[\w]+)""",
      """セキュリティが有効な({group_type}[^\s]+) グループにメンバーが追加されました。""",
      """サブジェクト:.+?アカウント名:\s{1,100}({user}[^\s]+)""",
      """アカウント ドメイン:\s{1,100}({user_domain}[^\s]+)""",
      """ログオン ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}""",
      """メンバー:\s{1,100}セキュリティ ID:\s{1,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s{1,100}アカウント名:""",
      """メンバー:.+?アカウント名:\s{0,100}({account_dn}.+?)\s{0,100}グループ:""",
      """グループ:\s{1,100}セキュリティ ID:\s{1,100}({group_id}[^\s]+)""",
      """グループ:.+?グループ名:\s{1,100}({group_name}.+?)?\s{1,100}グループ ドメイン:""",
      """グループ:.+?グループ ドメイン:\s{1,100}({group_domain}[^\s]+)"""]
    DupFields = [ "host->computer_name" ]
  }
```