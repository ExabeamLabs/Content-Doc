#### Parser Content
```Java
{
Name = s-cyberark-password-reset
  DataType = "account-password-reset"
  Conditions = [ """%CYBERARK:""", """Message="Set Password""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;UserName="(|({target_user}[^"]+))"""",
    """;LogonDomain="(|({target_domain}[^"]+))"""",
  ]
  DupFields=[ "host->dest_host" ]
}
```