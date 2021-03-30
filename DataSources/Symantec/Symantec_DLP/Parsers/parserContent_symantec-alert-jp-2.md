#### Parser Content
```Java
{
Name = symantec-alert-jp-2
  Conditions = [ """ウイルスが見つかりました,""", """重要度:""" ]
  Fields = ${SymantecParserTemplates.symantec-alert-jp.Fields}[
    """イベント時間:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """SymantecServer:\s*({alert_type}[^,]+)""",
    """信頼度:\s*({additional_info}[^,]+)""",
    """重要度:\s*({alert_severity}[^\s,]+)""",
    """件数:[^,]*,({malware_url}[^,]+)""",
    """,IP アドレス:\s*({src_ip}[a-fA-F\d.:]+)""",
    """送信元 IP:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """({file_path}({file_parent}[^,]*?[\\\/]+)?(|({file_name}[^\\\/,]*?(\.({file_ext}\w*))?)?)),,実際の処理"""
  ]
  DupFields = [ "host->src_host" ]
}
symantec-alert-jp = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({alert_type}[^,]+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """,IP アドレス:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """,コンピュータ名:\s*({dest_host}[^,]+?)(,|\s*$)""",
    """,リスク名:\s*({alert_name}[^,]+?)(,|\s*$)""",
    """,実際の処理:\s*({action}[^,]+?)(,|\s*$)""",
    """,ユーザー:\s*({user}[^,]+?)(,|\s*$)""",
    """,カテゴリセット:\s*({category}[^,]+?)(,|\s*$)""",
    """,カテゴリの種類:\s*({threat_category}[^,]+?)(,|\s*$)""",
    """,アプリケーションハッシュ:\s*({sha256}[^,]+?)(,|\s*$)""",
    """,件数:[^,]*,({file_path}({file_parent}[^,]*?[\\\/]+)?({file_name}[^\.\\\/]*?(\.({file_ext}\w+))?))\s*(,|\s*$)""",
  ]

```