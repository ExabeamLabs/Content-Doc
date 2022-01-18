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
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4663),({host}[\w\-.]{1,2000})""",
    """サブジェクト:\s{0,100}\S+\s{0,100}ID:\s{0,100}({user_sid}\S+)""",
    """アカウント名:\s{0,100}({user}[^\s]{1,2000})""",
    """アカウント ドメイン:\s{0,100}({domain}[^\s]{1,2000})""",
    """ログオン ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """オブジェクトの種類:\s{0,100}({file_type}[^\s]{1,2000})""",
    """オブジェクト名:\s{0,100}({file_path}.+?)\s{0,100}ハンドル ID:""",
    """オブジェクト名:\s{0,100}({file_parent}.+?)({file_name}([^\\:]{1,2000}(?=\.))({file_ext}\.[^\\:]{1,2000}?)?|[^\\:]{1,2000}?)\s{0,100}ハンドル ID:""",
    """プロセス名:\s{0,100}({process}({directory}.+?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{0,100}アクセス要求情報:""",
    """アクセス:\s{0,100}({accesses}.+?)\s{0,100}アクセス マスク:""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```