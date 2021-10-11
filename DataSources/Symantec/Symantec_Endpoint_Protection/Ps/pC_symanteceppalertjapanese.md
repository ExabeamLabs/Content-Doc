#### Parser Content
```Java
{
Name = symantec-epp-alert-japanese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,SHA-256:""", """,MD-5:""", """,CIDS シグネチャ文字列:""", """,アプリケーション:""", """シグネチャ ID:""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),[^,]{0,2000},({host}[\w\-.]{1,2000}),SHA-256:""",
    """SHA-256:\s{0,100}({sha256_sum}[^\s,]{1,2000})""",
    """MD-5:\s{0,100}({md5_sum}[^\s,]{1,2000})""",
    """,MD-5:\s{0,100}[^,:\s]{0,2000},\s{0,100}({alert_name}[^,]{1,2000})""",
    """,CIDS シグネチャ文字列:\s{0,100}[^,:]{0,2000}:\s{0,100}({alert_name}[^,]{1,2000})""",
    """ローカルポート\s{0,100}(0|({src_port}\d{1,100}))""",
    """リモートポート\s{0,100}(0|({dest_port}\d{1,100}))""",
    """,ローカル:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """アプリケーション:\s{0,100}(|({malware_url}[^,]{1,2000}?[\\\/]{1,2000}({malware_file_name}[^\\\/,]{1,2000}))),""",
    """ユーザー:\s{0,100}({user}[^\s,]{1,2000}),""",
    """ドメイン:\s{0,100}({domain}[^\s,]{1,2000}),""",
    """シグネチャ ID:\s{0,100}({signature_id}[^\s,]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```