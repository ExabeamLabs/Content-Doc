#### Parser Content
```Java
{
Name = s-symantec-epp-alert
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """スキャンが開始されました""", """,スキャン ID:""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),スキャン ID:""",
      """スキャン ID:\s{0,100}({alert_id}\d{1,100})""",
      """ユーザー 1:\s{0,100}(SYSTEM|({user}[^\s,]{1,2000}))""",
      """IP アドレス:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """コンピュータ:\s{0,100}({src_host}[\w\-.]{1,2000})""",
      """,({alert_name}[^,]{1,2000}),スキャン 完了:""",
      """グループ:\s{0,100}({malware_url}[^,]{1,2000})""",
      """脅威:\s{0,100}({threat_num}[^,]{1,2000})""",
      """感染:\s{0,100}({infection_num}[^,]{1,2000})""",
    ]
    DupFields = [ "alert_name->alert_type" ]
  }
```