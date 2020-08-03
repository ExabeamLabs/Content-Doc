#### Parser Content
```Java
{
Name = cef-microsoft-auth-attempt
  DataType = "authentication-attempt"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Credentials validation"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """\Wext_resolvedActor_name=({user_lastname}[^,=]+),\s*({user_firstname}.+?)(\s*\(Contract\))?(\s+\w+=|\s*$)"""
  ]
}
```