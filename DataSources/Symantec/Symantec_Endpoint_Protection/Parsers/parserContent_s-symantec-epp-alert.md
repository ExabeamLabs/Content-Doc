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
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),スキャン ID:""",
      """スキャン ID:\s{0,100}({alert_id}\d{1,100})""",
      """ユーザー 1:\s{0,100}(SYSTEM|({user}[^\s,]+))""",
      """IP アドレス:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
      """コンピュータ:\s{0,100}({src_host}[\w\-.]+)""",
      """,({alert_name}[^,]+),スキャン 完了:""",
      """グループ:\s{0,100}({malware_url}[^,]+)""",
      """脅威:\s{0,100}({threat_num}[^,]+)""",
      """感染:\s{0,100}({infection_num}[^,]+)""",
    ]
    DupFields = [ "alert_name->alert_type" ]
  }
```