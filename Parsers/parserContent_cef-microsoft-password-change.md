#### Parser Content
```Java
{
Name = cef-microsoft-password-change
  DataType = "password-change"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Change password:""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"description":"[^"]*?device <b>({src_host}[^"<]+)""",
  ]
}
```