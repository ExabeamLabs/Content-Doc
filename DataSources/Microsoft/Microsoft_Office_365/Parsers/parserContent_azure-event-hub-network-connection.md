#### Parser Content
```Java
{
Name = azure-event-hub-network-connection
  DataType = "network-connection"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceNetworkEvents|""", """vmid=""", """@timestamp""", """@metadata"""]
  Fields = ${MSParserTemplates.azure-event-hub-network-events.Fields} [
  ]
}
```