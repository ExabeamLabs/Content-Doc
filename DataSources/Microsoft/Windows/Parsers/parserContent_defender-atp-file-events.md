#### Parser Content
```Java
{
Name = defender-atp-file-events
  DataType = "file-operations"
  Conditions = [  """"Type":"AdvancedHuntingDeviceFileEvents_CL""" ,"""TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
  DupFields = ["outcome->accesses"]
}
```