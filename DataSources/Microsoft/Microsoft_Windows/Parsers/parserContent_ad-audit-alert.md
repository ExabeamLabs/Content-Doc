#### Parser Content
```Java
{
Name = ad-audit-alert
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """Category = ADAPAlerts""", """ALERT_PROFILE =""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """\WUNIQUE_ID\s{0,100}=\s{0,100}({alert_id}\d{1,100})""",
    """\WTIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """\WSOURCE\s{0,100}=\s{0,100}(?:User Behaviour Analytics|({src_host}[\w\-.]{1,2000}))""",
    """\WALERT_PROFILE\s{0,100}=\s{0,100}({alert_type}.+?)\s{0,100}\]""",
    """\WSEVERITY\s{0,100}=\s{0,100}({alert_severity}\d{1,100})""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}.+?\soccured for\s{1,100}({user}[^\s]{1,2000})\s""",
    """\WFORMAT_MESSAGE\s{0,100}=.+?host:(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|({dest_host}[^\s]{1,2000}))\s{1,100}was accessed by user:({user}[^\s]{1,2000})\s""",
    """\WFORMAT_MESSAGE\s{0,100}=.+?\sfor User\s{0,100}'({user}[^']{1,2000})'\s{0,100}in\s{0,100}'(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|({dest_host}[^\s']{1,2000}))'""",
    """\WFORMAT_MESSAGE\s{0,100}=.+?\swas done by\s{1,100}({user}[^\s]{1,2000})\s""",
    """\WFORMAT_MESSAGE\s{0,100}=.+?was modified by\s{1,100}'(({domain}[^'\\]{1,2000})\\)?({user}[^\s\\']{1,2000})'""",
    """\WFORMAT_MESSAGE\s{0,100}=.+?\s{1,100}occured on\s{1,100}(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|({dest_host}[^\s]{1,2000}))\s{1,100}""",
    """\WDOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]{1,2000})""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}({additional_info}.+?)\s{0,100}\]"""
  ]
  DupFields=[ "alert_type->alert_name" ]
}
```