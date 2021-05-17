#### Parser Content
```Java
{
Name = s-cyberark-password-reset
  DataType = "account-password-reset"
  Conditions = [ """%CYBERARK:""", """Message="Set Password""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;UserName="(|({target_user}[^"]{1,2000}))"""",
    """;LogonDomain="(|({target_domain}[^"]{1,2000}))"""",
  ]
  DupFields=[ "host->dest_host" ]
}
```