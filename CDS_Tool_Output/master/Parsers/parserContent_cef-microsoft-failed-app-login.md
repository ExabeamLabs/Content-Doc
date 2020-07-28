#### Parser Content
```Java
{
Name = cef-microsoft-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Failed log on """ ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"description":"Failed log on \(({failure_reason}[^\)]+)""",
    """\Wext_failedUserData_userName=(|({user_email}[^=@]+?@[^=]+?)|({user}.+?))(\s+\w+=|\s*$)"""
  ]
}
```