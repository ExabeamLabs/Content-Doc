#### Parser Content
```Java
{
Name = beyondtrust-pi-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Privileged Identity|""", """|EVENT_ID_WEBAPP_LOGIN|""" ]
  Fields = ${BeyondTrustParserTemplates.beyondtrust-pi-events.Fields}[
    """Impersonating user (({target_domain}[^\\]+)(\\)+)?({target_user}[^\s)]+)\)"""
]
}
```