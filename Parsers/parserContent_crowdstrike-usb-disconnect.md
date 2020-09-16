#### Parser Content
```Java
{
Name = crowdstrike-usb-disconnect
  DataType = "usb-activity"
  Conditions = [ """"event_simpleName":"DcUsbDeviceDisconnected""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)""""
  """DcUsbDevice({activity}Disconnected)"""
  """"event_simpleName":"({activity_details}[^"]+)"""
  """"DeviceInstanceId":"({device_id}[^"]+)"""
  """"DevicePropertyDeviceDescription":"({device_type}[^"]+)"""
  ]
}
```