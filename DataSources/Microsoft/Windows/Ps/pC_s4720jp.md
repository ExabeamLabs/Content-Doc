#### Parser Content
```Java
{
Name = s-4720-jp
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-account-created"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [  "ユーザー アカウントが作成されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4720),""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000},)?ユーザー アカウントが作成されました。""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """EventCode=({event_code}\w+)""",
      """サブジェクト:.+?アカウント名:\s{1,100}({user}.+?)\s{1,100}アカウント ドメイン:\s{1,100}({user_domain}[^\s]{1,2000}).+?ログオン ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """新しいアカウント:.+?セキュリティ ID:\s{1,100}({account_id}[^\s]{1,2000})\s{1,100}アカウント名:\s{1,100}({account_name}.+?)\s{1,100}アカウント ドメイン:\s{1,100}({account_domain}[^\s]{1,2000})""" ]
    DupFields = [ "computer_name->host" ]
  }
```