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
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),スキャン ID:""",
      """スキャン ID:\s*({alert_id}\d+)""",
      """ユーザー 1:\s*(SYSTEM|({user}[^\s,]+))""",
      """IP アドレス:\s*({src_ip}[A-Fa-f:\d.]+)""",
      """コンピュータ:\s*({src_host}[\w\-.]+)""",
      """,({alert_name}[^,]+),スキャン 完了:""",
      """グループ:\s*({malware_url}[^,]+)""",
      """脅威:\s*({threat_num}[^,]+)""",
      """感染:\s*({infection_num}[^,]+)""",
    ]
    DupFields = [ "alert_name->alert_type" ]
  }
```