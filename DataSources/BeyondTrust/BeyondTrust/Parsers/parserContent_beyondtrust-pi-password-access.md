#### Parser Content
```Java
{
Name = beyondtrust-pi-password-access
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Privileged Identity|""", """|EVENT_ID_PASSWORD_""" ]
  Fields = ${BeyondTrustParserTemplates.beyondtrust-pi-events.Fields}[
    """for '*\(({dest_host}[^)]+)\)'\[?({target_domain}[^\\\]]+)\]?(\\)*({target_user}[^'\s]+)'""",
]
}
```