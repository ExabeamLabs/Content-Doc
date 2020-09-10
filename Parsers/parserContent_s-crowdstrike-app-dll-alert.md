#### Parser Content
```Java
{
Name = s-crowdstrike-app-dll-alert
  DataType = "alert"
  Conditions = [ """"event_simpleName":"ReflectiveDllLoaded"""", """|Skyformation|""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)"""",
  """"name":"({alert_name}[^"]+?)""""
  """"CommandLine":"({command_line}.+?[^\\])""""
  ]
}
${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
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
${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
  Name = crowdstrike-usb-connect
  DataType = "usb-activity"
  Conditions = [ """"event_simpleName":"DcUsbDeviceConnected""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)""""
  """DcUsbDevice({activity}Connected)"""
  """"event_simpleName":"({activity_details}[^"]+)"""
  """"DeviceInstanceId":"({device_id}[^"]+)"""
  """"DevicePropertyDeviceDescription":"({device_type}[^"]+)"""
  ]
}
${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
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

${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
  Name = crowdstrike-win-task-created
  DataType = "windows-task-created"
  Conditions = [ """"event_simpleName":"ScheduledTaskRegistered""", """"event_platform":"Win""""]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"TaskName":"({task_name}[^"]+)"""
  ]
}

${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
  Name = crowdstrike-modify-binary
  DataType = "file-operations"
  Conditions = [ """event_simpleName""", """ModifyServiceBinary""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"ServiceImagePath":"({file_path}({file_parent}[^"]*?\\+)({file_name}[^\\\s"]+?\.({file_ext}[^\\\s"\.]+?)))(\s|")"""
    """"ServiceObjectName":"({additional_info}[^"]+)"""
    """({accesses}Modify)"""
  ]
}

{
  Name = crowdstrike-app-activity
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"UserActivityAuditEvent"""", """"OperationName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"UserId":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s*"({user}[^"@]+)"""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """"ServiceName":\s*"({resource}[^"]+)""",
    """({app}CrowdStrike)""",
    """"OperationName":\s*"({activity}[^",]+)""",
    """"AuditKeyValues":\[({additional_info}.+?)\]""",
    """"AuditKeyValues":[^\]]+?"Value(String)?":"({object}.*?[^\\])"(,|\})""",
  ]
}
```