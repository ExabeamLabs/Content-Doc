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
```