#### Parser Content
```Java
{
Name = s-cyberark-security-alert-1
  DataType = "alert"
  Conditions = [ """%CYBERARK:""", """Message="Non authorized impersonation """, """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;Severity="(|({alert_severity}[^"]+))"""",
    """;File="(|({malware_url}[^"]+))"""",
  ]
  DupFields = [ "activity->alert_name", "activity->alert_type" ]
}
```