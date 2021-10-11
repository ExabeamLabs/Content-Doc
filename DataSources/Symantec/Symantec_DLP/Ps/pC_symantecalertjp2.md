#### Parser Content
```Java
{
Name = symantec-alert-jp-2
  Conditions = [ """ウイルスが見つかりました,""", """重要度:""" ]
  Fields = ${SymantecParserTemplates.symantec-alert-jp.Fields}[
    """イベント時間:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """SymantecServer:\s{0,100}({alert_type}[^,]{1,2000})""",
    """信頼度:\s{0,100}({additional_info}[^,]{1,2000})""",
    """重要度:\s{0,100}({alert_severity}[^\s,]{1,2000})""",
    """件数:[^,]{0,2000}
symantec-alert-jp = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({alert_type}[^,]{1,2000})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """,IP アドレス:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """,コンピュータ名:\s{0,100}({dest_host}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,リスク名:\s{0,100}({alert_name}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,実際の処理:\s{0,100}({action}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,ユーザー:\s{0,100}({user}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,カテゴリセット:\s{0,100}({category}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,カテゴリの種類:\s{0,100}({threat_category}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,アプリケーションハッシュ:\s{0,100}({sha256}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """,件数:[^,]{0,2000},({file_path}({file_parent}[^,]{0,2000}?[\\\/]{1,2000})?({file_name}[^\.\\\/]{0,2000}?(\.({file_ext}\w+))?))\s{0,100}(,|\s{0,100}$)""",
  ]

```