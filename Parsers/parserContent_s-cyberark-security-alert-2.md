#### Parser Content
```Java
{
Name = s-cyberark-security-alert-2
  DataType = "alert"
  Conditions = [ """%CYBERARK:""", """Message="Keystroke logging""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;Severity="(|({alert_severity}[^"]+))"""",
    """;File="(|({malware_url}[^"]+))"""",
  ]
  DupFields = [ "activity->alert_name", "activity->alert_type" ]
}
```