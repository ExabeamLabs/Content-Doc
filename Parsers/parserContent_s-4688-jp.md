#### Parser Content
```Java
{
Name = s-4688-jp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ "4688", "新しいプロセスが作成されました。" ]
  Fields = [
    """\sTimeGenerated=({time}\d+)""",
    """Computer(Name)?=({host}[\w.\-]+)""",
    """({event_code}4688)""",
    """({event_name}新しいプロセスが作成されました)。.+?セキュリティ ID:\s*({user_sid}.*?)\s*アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*ターゲット サブジェクト:""",
    """新しいプロセス ID:\s*({process_guid}.+?)\s*新しいプロセス名:""",
    """作成元プロセス ID:\s*({parent_process_guid}.+?)\s*作成元プロセス名:"""
  ]
}
```