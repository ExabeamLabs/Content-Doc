#### Parser Content
```Java
{
Name = s-cyberark-security-alert-2
  DataType = "alert"
  Conditions = [ """%CYBERARK:""", """Message="Keystroke logging""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;Severity="(|({alert_severity}[^"]{1,2000}))"""",
    """;File="(|({malware_url}[^"]{1,2000}))"""",
  ]
  DupFields = [ "activity->alert_name", "activity->alert_type" ]
}
```