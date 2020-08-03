#### Parser Content
```Java
{
Name = s-cyberark-password-change-failed
  DataType = "password-change"
  Conditions = [ """%CYBERARK:""", """Message="CPM Change Password Failed"""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;UserName="(|({target_user}[^"]+))"""",
    """;LogonDomain="(|({target_domain}[^"]+))"""",
  ]
  DupFields=[ "host->dest_host" ]
}
```