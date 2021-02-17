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
      """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4672),""",
      """({host}[\w.\-]+),新しいログオンに特権が割り当てられました。""",
      """アカウント名:\s*({user}.*?)\s*アカウント ドメイン:\s*({domain}.*?)\s*ログオン ID:\s*({logon_id}.*?)\s*特権:\s*({privileges}.*?)\s*($|")"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```