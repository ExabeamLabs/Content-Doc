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
    """SHA-256:\s*({sha256_sum}[^\s,]+)""",
    """MD-5:\s*({md5_sum}[^\s,]+)""",
    """,MD-5:\s*[^,:\s]*,\s*({alert_name}[^,]+)""",
    """,CIDS シグネチャ文字列:\s*[^,:]*:\s*({alert_name}[^,]+)""",
    """ローカルポート\s*(0|({src_port}\d+))""",
    """リモートポート\s*(0|({dest_port}\d+))""",
    """,ローカル:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """アプリケーション:\s*(|({malware_url}[^,]+?[\\\/]+({malware_file_name}[^\\\/,]+))),""",
    """ユーザー:\s*({user}[^\s,]+),""",
    """ドメイン:\s*({domain}[^\s,]+),""",
    """シグネチャ ID:\s*({signature_id}[^\s,]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```