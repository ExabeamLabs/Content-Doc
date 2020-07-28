#### Parser Content
```Java
{
Name = ad-audit-5141
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 5141""", """User Account Deleted""" ]
}

${ADAuditParserTemplates.ad-audit-ds-access} {
  Name = ad-audit-4742
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4742""", """REMARKS = A computer account was changed.""" ]
}

${ADAuditParserTemplates.ad-audit-ds-access} {
  Name = ad-audit-4738
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4738""", """REMARKS = A user account was changed.""" ]
}

${ADAuditParserTemplates.ad-audit-ds-access} {
  Name = ad-audit-4662
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4662""", """REMARKS = Control Access : Computer""" ]
}

{
  Name = ad-audit-alert
  Vendor = AD Audit
  Product = AD Audit
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """Category = ADAPAlerts""", """ALERT_PROFILE =""" ]
  Fields = [
    """({host}[\w\-.]+) ADAuditPlus""",
    """\WUNIQUE_ID\s*=\s*({alert_id}\d+)""",
    """\WTIME_GENERATED\s*=\s*({time}\d+)""",
    """\WSOURCE\s*=\s*(?:User Behaviour Analytics|({src_host}[\w\-.]+))""",
    """\WALERT_PROFILE\s*=\s*({alert_type}.+?)\s*\]""",
    """\WSEVERITY\s*=\s*({alert_severity}\d+)""",
    """\WFORMAT_MESSAGE\s*=\s*.+?\soccured for\s+({user}[^\s]+)\s""",
    """\WFORMAT_MESSAGE\s*=.+?host:(?:({dest_ip}[A-Fa-f:\d.]+)|({dest_host}[^\s]+))\s+was accessed by user:({user}[^\s]+)\s""",
    """\WFORMAT_MESSAGE\s*=.+?\sfor User\s*'({user}[^']+)'\s*in\s*'(?:({dest_ip}[A-Fa-f:\d.]+)|({dest_host}[^\s']+))'""",
    """\WFORMAT_MESSAGE\s*=.+?\swas done by\s+({user}[^\s]+)\s""",
    """\WFORMAT_MESSAGE\s*=.+?was modified by\s+'(({domain}[^'\\]+)\\)?({user}[^\s\\']+)'""",
    """\WFORMAT_MESSAGE\s*=.+?\s+occured on\s+(?:({dest_ip}[A-Fa-f:\d.]+)|({dest_host}[^\s]+))\s+""",
    """\WDOMAIN\s*=\s*({domain}[^\s\]]+)""",
    """\WFORMAT_MESSAGE\s*=\s*({additional_info}.+?)\s*\]"""
  ]
  DupFields=[ "alert_type->alert_name" ]
}
```