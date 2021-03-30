#### Parser Content
```Java
{
Name = s-cyberark-app-login
  DataType = "app-login"
  Conditions = [ """%CYBERARK:""", """Message="Logon""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;CPMStatus="(|({outcome}[^"]+))"""",
    """;Reason="(|({failure_reason}[^"]+))""""
  ]
  DupFields=[ "host->dest_host" ]
}
```