#### Parser Content
```Java
{
Name = cef-defender-atp-alert
  DataType = "alert"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceAlertEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [ 
     """Category":\s{0,100}"({alert_name}[^"]{1,2000})""",
     """Title":\s{0,100}"({additional_info}[^"]{1,2000})""",
     """FileName":\s{0,100}"({process_name}[^"]{1,2000})""",
     """Severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
     """AlertId":\s{0,100}"({alert_id}[^"]{1,2000})"""
     """DeviceName":\s{0,100}"({src_host}[^"]{1,2000})""",
     """RemoteUrl":\s{0,100}"({malware_url}[^"]{1,2000})""",
     """MD5":"({md5}[^"]{1,2000})"""
  ]
  DupFields = [ "category->alert_type" ]
}
```