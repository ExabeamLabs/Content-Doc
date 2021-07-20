#### Parser Content
```Java
{
Name = s-4688-jp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """4688""", """新しいプロセスが作成されました。""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM|am|pm))"""
    """Computer(Name)?=({host}[\w.\-]{1,2000})""",
    """({event_code}4688)""",
    """({event_name}新しいプロセスが作成されました)。.+?セキュリティ ID:\s{0,100}({user_sid}.*?)\s{0,100}アカウント名:\s{0,100}({user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}ターゲット サブジェクト:""",
    """新しいプロセス ID:\s{0,100}({process_guid}.+?)\s{0,100}新しいプロセス名:""",
    """作成元プロセス ID:\s{0,100}({parent_process_guid}.+?)\s{0,100}作成元プロセス名:"""
    """新しいプロセス名:\s{0,100}({process}({directory}.+?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{0,100}トークン昇格の種類:""",
    """プロセスのコマンド ライン:\s{0,100}(\s{1,100}|({command_line}[^=]{1,2000}))\s{1,100}トークン昇格の種類は"""
  ]
  DupFields = [ "directory->process_directory","directory->path" ]
}
```