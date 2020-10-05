#### Parser Content
```Java
{
Name = azure-event-hub-process-events
  DataType = "process-created"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceProcessEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"ProcessCreated""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
  ]
}
```