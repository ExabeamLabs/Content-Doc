#### Parser Content
```Java
{
Name = azure-event-hub-process-events
  DataType = "process-created"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceProcessEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"ProcessCreated""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```