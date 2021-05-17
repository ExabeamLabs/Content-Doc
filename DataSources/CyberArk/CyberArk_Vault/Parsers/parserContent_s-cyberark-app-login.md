#### Parser Content
```Java
{
Name = s-cyberark-app-login
  DataType = "app-login"
  Conditions = [ """%CYBERARK:""", """Message="Logon""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;CPMStatus="(|({outcome}[^"]{1,2000}))"""",
    """;Reason="(|({failure_reason}[^"]{1,2000}))""""
  ]
  DupFields=[ "host->dest_host" ]
}
```