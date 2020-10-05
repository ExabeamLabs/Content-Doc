#### Parser Content
```Java
{
Name = s-sep-mobile-alert-1
  Conditions = [ """"type": "Malware"""" , """current_risk_warnings""", """package_name""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"email":\s*"({user_email}[^"]+)",\s*"name":\s*"({user_fullname}[^"]+)"""",
    """"severity":\s*"({alert_severity}[^"]+)",\s*"id":\s*({alert_id}\d+)""",
    """"package_name":\s*"({alert_type}[^"]+)""",
    """"apk_hash":\s*"({md5}[^"]+)""",
  ]
}
```