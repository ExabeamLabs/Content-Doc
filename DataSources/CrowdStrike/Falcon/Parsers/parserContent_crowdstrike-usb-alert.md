#### Parser Content
```Java
{
Name = crowdstrike-usb-alert
  DataType = "dlp-alert"
  Conditions = [ """"event_simpleName":"DcUsbDevicePolicyViolation"""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)""""
  """"name":"({alert_name}[^"]+?)""""
  """"DeviceProduct":"({additional_info}[^"]+)"""
  """"DeviceInstanceId":"({target}[^"]+)"""
  
  ]
}
```