#### Parser Content
```Java
{
Name = s-4663-jp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ",4663,", "オブジェクトへのアクセスが試行されました。" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4663),({host}[\w\-.]+)""",
    """サブジェクト:\s*\S+\s*ID:\s*({user_sid}\S+)""",
    """アカウント名:\s*({user}[^\s]+)""",
    """アカウント ドメイン:\s*({domain}[^\s]+)""",
    """ログオン ID:\s*({logon_id}[^\s]+)""",
    """オブジェクトの種類:\s*({file_type}[^\s]+)""",
    """オブジェクト名:\s*({file_path}.+?)\s*ハンドル ID:""",
    """オブジェクト名:\s*({file_parent}.+?)({file_name}([^\\:]+(?=\.))({file_ext}\.[^\\:]+?)?|[^\\:]+?)\s*ハンドル ID:""",
    """プロセス名:\s*({process}({directory}.+?[\\\/])?({process_name}[^\\\/"]+?))\s*アクセス要求情報:""",
    """アクセス:\s*({accesses}.+?)\s*アクセス マスク:""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```