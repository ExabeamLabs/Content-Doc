#### Parser Content
```Java
{
Name = cef-microsoft-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Log on"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """\Wext_resolvedActor_name=({user_lastname}[^,=]+),\s*({user_firstname}.+?)(\s*\([^\(\)]+\))?(\s+\w+=|\s*$)""",
    """device <b>({dest_host}[^<]+)""",
  ]
}
```