#### Parser Content
```Java
{
Name = jp-member-added-3
  Conditions = [ "4756", "セキュリティが有効なユニバーサル" ]

jp-member-added = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}\d{1,100}),(?!\d{1,100})({host}[\w\-.]{1,2000}),.+?グループにメンバーが追加されました。""",
    """サブジェクト:.+?アカウント名:\s{1,100}({user}[^\s]{1,2000})""",
    """アカウント ドメイン:\s{1,100}({user_domain}[^\s]{1,2000})""",
    """ログオン ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """メンバー:\s{1,100}セキュリティ ID:\s{1,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}.+?)|(?:.+?))\s{1,100}アカウント名:""",
    """メンバー:.+?アカウント名:\s{0,100}({account_dn}(?i)(cn)=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))\s{0,100}グループ:""",
    """グループ:\s{1,100}セキュリティ ID:\s{1,100}({group_id}[^\s]{1,2000})""",
    """グループ:.+?アカウント名:\s{1,100}({group_name}.+?)?\s{1,100}アカウント ドメイン:""",
    """グループ:.+?グループ名:\s{1,100}({group_name}.+?)?\s{1,100}グループ ドメイン:""",
    """グループ:.+?グループ ドメイン:\s{1,100}({group_domain}[^\s]{1,2000})""",
    """セキュリティが有効な({group_type}[^\s]{1,2000})\s{1,100}グループにメンバーが追加されました。""",
  ]
  DupFields = [ "host->dest_host" 
}
```