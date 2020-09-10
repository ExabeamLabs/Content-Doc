#### Parser Content
```Java
{
Name = cef-microsoft-remote-logon
  DataType = "remote-logon"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Remote desktop: device""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """\Wext_resolvedActorAccount_name=({user_lastname}[^,=]+),\s*({user_firstname}.+?)(\s*\([^\(\)]+\))?(\s+\w+=|\s*$)""",
    """device <b>({dest_host}[^<]+)"""
  ]
}
```