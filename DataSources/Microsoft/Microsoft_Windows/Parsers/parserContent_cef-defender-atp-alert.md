#### Parser Content
```Java
{
Name = cef-defender-atp-alert
  DataType = "alert"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceAlertEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [ 
     """Category":\s{0,100}"({alert_name}[^"]+)""",
     """Title":\s{0,100}"({additional_info}[^"]+)""",
     """FileName":\s{0,100}"({process_name}[^"]+)""",
     """Severity":\s{0,100}"({alert_severity}[^"]+)""",
     """AlertId":\s{0,100}"({alert_id}[^"]+)"""
     """DeviceName":\s{0,100}"({src_host}[^"]+)""",
     """RemoteUrl":\s{0,100}"({malware_url}[^"]+)""",
     """MD5":"({md5}[^"]+)"""
  ]
  DupFields = [ "category->alert_type" ]
}
```