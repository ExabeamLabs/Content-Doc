#### Parser Content
```Java
{
Name = s-4672-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [  "4672", "新しいログオンに特権が割り当てられました。", "特権:"]
    Fields = [
      """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4672),""",
      """({host}[\w.\-]{1,2000}),新しいログオンに特権が割り当てられました。""",
      """アカウント名:\s{0,100}({user}.*?)\s{0,100}アカウント ドメイン:\s{0,100}({domain}.*?)\s{0,100}ログオン ID:\s{0,100}({logon_id}.*?)\s{0,100}特権:\s{0,100}({privileges}.*?)\s{0,100}($|")"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```