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
    """Computer(Name)?=({host}[\w.\-]+)""",
    """({event_code}4688)""",
    """({event_name}新しいプロセスが作成されました)。.+?セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット サブジェクト:""",
    """新しいプロセス ID:\s*({process_guid}.+?)\s*新しいプロセス名:""",
    """作成元プロセス ID:\s*({parent_process_guid}.+?)\s*作成元プロセス名:"""
    """新しいプロセス名:\s*({process}({directory}.+?[\\\/])?({process_name}[^\\\/"]+?))\s*トークン昇格の種類:""",
    """プロセスのコマンド ライン:\s*(\s+|({command_line}[^=]+))\s+トークン昇格の種類は"""
  ]
  DupFields = [ "directory->process_directory","directory->path" ]
}
```