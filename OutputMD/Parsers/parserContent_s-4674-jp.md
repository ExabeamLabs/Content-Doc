#### Parser Content
```Java
{
Name = s-4674-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "4674", "特権のあるオブジェクトで操作が試行されました。", "特権:"]
    Fields = [
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4674),""",
      """({host}[\w.\-]+),特権のあるオブジェクトで操作が試行されました。""",
      """アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*オブジェクト:""",
      """オブジェクト サーバー:\s*({object_server}.*?)\s*オブジェクトの種類:\s*(?:-|({object_type}.*?))\s*オブジェクト名:\s*(?:-|({object}.*?))\s*オブジェクト ハンドル:""",
      """プロセス名:\s+({process}({directory}.*?\\)({process_name}[^\\]*?))\s+要求された操作:""",
      """望ましいアクセス権:\s*({accesses}.*?)\s*特権:\s*({privileges}.*?)\s*($|")"""
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```