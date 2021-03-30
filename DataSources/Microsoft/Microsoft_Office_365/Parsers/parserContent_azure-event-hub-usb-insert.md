#### Parser Content
```Java
{
Name = azure-event-hub-usb-insert
  DataType = "usb-insert"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UsbDriveMount""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
     """SerialNumber\\"+:\\"+({device_id}\d+)"""
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```