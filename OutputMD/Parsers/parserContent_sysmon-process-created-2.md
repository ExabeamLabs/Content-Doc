#### Parser Content
```Java
{
Name = sysmon-process-created-2
  Conditions = [ """Process Create: """, """ ProcessGuid: """, """ ParentProcessGuid: """ ]
  DataType = "process-created"
  Fields = ${MicrosoftParserTemplates.sysmon-process-events.Fields}[
  ]
}
```