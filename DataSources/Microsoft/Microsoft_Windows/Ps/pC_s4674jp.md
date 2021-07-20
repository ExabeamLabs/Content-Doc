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
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4674),""",
      """({host}[\w.\-]{1,2000}),特権のあるオブジェクトで操作が試行されました。""",
      """アカウント名:\s{0,100}({user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}オブジェクト:""",
      """オブジェクト サーバー:\s{0,100}({object_server}.*?)\s{0,100}オブジェクトの種類:\s{0,100}(?:-|({object_type}.*?))\s{0,100}オブジェクト名:\s{0,100}(?:-|({object}.*?))\s{0,100}オブジェクト ハンドル:""",
      """プロセス名:\s{1,100}({process}({directory}.*?\\)({process_name}[^\\]{0,2000}?))\s{1,100}要求された操作:""",
      """望ましいアクセス権:\s{0,100}({accesses}.*?)\s{0,100}特権:\s{0,100}({privileges}.*?)\s{0,100}($|")"""
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```