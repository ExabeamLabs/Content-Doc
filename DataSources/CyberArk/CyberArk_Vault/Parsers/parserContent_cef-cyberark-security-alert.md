#### Parser Content
```Java
{
Name = cef-cyberark-security-alert
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a zzz"
  Conditions = [  """CEF:""", """|Cyber-Ark|Vault|""", """|Privileged Threat Analytics Event|""" ]
  Fields = [
    """\Wact=({alert_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Date=\[({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+ \w+)\]""",
    """EventName=\[({alert_name}.+?)\]""",
    """TargetAddress=\[(?:None|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))\]""",
    """SourceAddress=\[(?:None|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))\]""",
    """\Wduser=({user}[^=@]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=({user_email}[^=@]{1,2000}@[^=@]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Score=\[({alert_severity}\d{1,100})\]""",
    """AuditId=\[({alert_id}.+?)\]""",
  ]
}
```