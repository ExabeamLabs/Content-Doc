#### Parser Content
```Java
{
Name = defender-atp-logon
  DataType = "app-login"
  Conditions = [  """"Type":"AdvancedHuntingDeviceLogonEvents_CL""" , """TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
}
```