#### Parser Content
```Java
{
Name = kaspersky-es-alert
  Vendor = Kaspersky Lab
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "alert"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """nId: """", """ EventDisplayName: """",""" wstrPar5: """" ]
  Fields = [
    """DeviceTime:\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """hostname:\s*"({host}[^"]+)""",
    """nId:\s*"({alert_id}[^"]+)""",
    """EventDisplayName:\s*"({alert_name}[^"]+)""",
    """wstrPar5:\s*"(null|({alert_name}[^"]+))""",
    """wstrPar2:\s*"(null|({malware_url}[^"]+))""",
    """wstrPar8:\s*"(null|({alert_severity}[^"]+))""",
    """User:\s+(({domain}[^\\]*)\\+)?({user}[^\\\s]+)\s*\(""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```