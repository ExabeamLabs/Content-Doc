#### Parser Content
```Java
{
Name = cef-defender-atp-alert
  DataType = "alert"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceAlertEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [ 
     """Category":\s*"({alert_name}[^"]+)""",
     """Title":\s*"({additional_info}[^"]+)""",
     """FileName":\s*"({process_name}[^"]+)""",
     """Severity":\s*"({alert_severity}[^"]+)""",
     """AlertId":\s*"({alert_id}[^"]+)"""
     """DeviceName":\s*"({src_host}[^"]+)""",
     """RemoteUrl":\s*"({malware_url}[^"]+)""",
     """MD5":"({md5}[^"]+)"""
  ]
  DupFields = [ "category->alert_type" ]
}
```