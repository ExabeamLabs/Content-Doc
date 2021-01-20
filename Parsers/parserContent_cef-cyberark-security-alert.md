#### Parser Content
```Java
{
Name = cef-cyberark-security-alert
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a zzz"
  Conditions = [  """CEF:""", """|Cyber-Ark|Vault|""", """|Privileged Threat Analytics Event|""" ]
  Fields = [
    """\Wact=({alert_type}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wfname=({additional_info}[^=]+?)(\s+\w+=|\s*$)""",
    """Date=\[({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+ \w+)\]""",
    """EventName=\[({alert_name}.+?)\]""",
    """TargetAddress=\[(?:None|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))\]""",
    """SourceAddress=\[(?:None|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))\]""",
    """\Wduser=({user}[^=@]+?)(\s+\w+=|\s*$)""",
    """\Wduser=({user_email}[^=@]+@[^=@]+?)(\s+\w+=|\s*$)""",
    """Score=\[({alert_severity}\d+)\]""",
    """AuditId=\[({alert_id}.+?)\]""",
  ]
}
```