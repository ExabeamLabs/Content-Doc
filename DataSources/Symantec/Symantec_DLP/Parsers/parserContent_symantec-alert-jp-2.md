#### Parser Content
```Java
{
Name = symantec-alert-jp-2
  Conditions = [ """ウイルスが見つかりました,""", """重要度:""" ]
  Fields = ${SymantecParserTemplates.symantec-alert-jp.Fields}[
    """イベント時間:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """SymantecServer:\s{0,100}({alert_type}[^,]+)""",
    """信頼度:\s{0,100}({additional_info}[^,]+)""",
    """重要度:\s{0,100}({alert_severity}[^\s,]+)""",
    """件数:[^,]*,({malware_url}[^,]+)""",
    """,IP アドレス:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """送信元 IP:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
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
    """,IP アドレス:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
    """,コンピュータ名:\s{0,100}({dest_host}[^,]+?)(,|\s{0,100}$)""",
    """,リスク名:\s{0,100}({alert_name}[^,]+?)(,|\s{0,100}$)""",
    """,実際の処理:\s{0,100}({action}[^,]+?)(,|\s{0,100}$)""",
    """,ユーザー:\s{0,100}({user}[^,]+?)(,|\s{0,100}$)""",
    """,カテゴリセット:\s{0,100}({category}[^,]+?)(,|\s{0,100}$)""",
    """,カテゴリの種類:\s{0,100}({threat_category}[^,]+?)(,|\s{0,100}$)""",
    """,アプリケーションハッシュ:\s{0,100}({sha256}[^,]+?)(,|\s{0,100}$)""",
    """,件数:[^,]*,({file_path}({file_parent}[^,]*?[\\\/]+)?({file_name}[^\.\\\/]*?(\.({file_ext}\w+))?))\s{0,100}(,|\s{0,100}$)""",
  ]

```