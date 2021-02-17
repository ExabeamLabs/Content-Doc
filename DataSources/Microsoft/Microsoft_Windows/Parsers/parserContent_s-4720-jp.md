#### Parser Content
```Java
{
Name = s-4720-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-created"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [  "ユーザー アカウントが作成されました。" ]
    Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4720),""",
      """(?!\d+)({host}[\w\-.]+),([^,]*,)?ユーザー アカウントが作成されました。""",
      """ComputerName=({computer_name}[\w.\-]+)""",
      """EventCode=({event_code}\w+)""",
      """サブジェクト:.+?アカウント名:\s+({user}.+?)\s+アカウント ドメイン:\s+({user_domain}[^\s]+).+?ログオン ID:\s+({logon_id}[^\s]+)""",
      """新しいアカウント:.+?セキュリティ ID:\s+({account_id}[^\s]+)\s+アカウント名:\s+({account_name}.+?)\s+アカウント ドメイン:\s+({account_domain}[^\s]+)""" ]
    DupFields = [ "computer_name->host" ]
  }
```