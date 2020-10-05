#### Parser Content
```Java
{
Name = azure-event-hub-process-events-1
  DataType = "process-created"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"PowerShellCommand""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
  ]
}
```