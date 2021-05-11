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
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),[^,]*,({host}[\w\-.]+),SHA-256:""",
    """SHA-256:\s{0,100}({sha256_sum}[^\s,]+)""",
    """MD-5:\s{0,100}({md5_sum}[^\s,]+)""",
    """,MD-5:\s{0,100}[^,:\s]*,\s{0,100}({alert_name}[^,]+)""",
    """,CIDS シグネチャ文字列:\s{0,100}[^,:]*:\s{0,100}({alert_name}[^,]+)""",
    """ローカルポート\s{0,100}(0|({src_port}\d{1,100}))""",
    """リモートポート\s{0,100}(0|({dest_port}\d{1,100}))""",
    """,ローカル:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """アプリケーション:\s{0,100}(|({malware_url}[^,]+?[\\\/]+({malware_file_name}[^\\\/,]+))),""",
    """ユーザー:\s{0,100}({user}[^\s,]+),""",
    """ドメイン:\s{0,100}({domain}[^\s,]+),""",
    """シグネチャ ID:\s{0,100}({signature_id}[^\s,]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```