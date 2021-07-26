#### Parser Content
```Java
{
Name = azure-event-hub-file-events
  DataType = "file-operations"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceFileEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"FolderPath":"({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}?(\.({file_ext}[^\\\/\.;"]{1,2000}))))""",
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```