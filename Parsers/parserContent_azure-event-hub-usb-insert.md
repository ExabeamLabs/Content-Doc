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
```