#### Parser Content
```Java
{
Name = kaspersky-es-alert
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "alert"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """nId: """", """ EventDisplayName: """",""" wstrPar5: """" ]
  Fields = [
    """DeviceTime:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """hostname:\s{0,100}"({host}[^"]+)""",
    """nId:\s{0,100}"({alert_id}[^"]+)""",
    """EventDisplayName:\s{0,100}"({alert_name}[^"]+)""",
    """wstrPar5:\s{0,100}"(null|({alert_name}[^"]+))""",
    """wstrPar2:\s{0,100}"(null|({malware_url}[^"]+))""",
    """wstrPar8:\s{0,100}"(null|({alert_severity}[^"]+))""",
    """User:\s{1,100}(({domain}[^\\]*)\\+)?({user}[^\\\s]+)\s{0,100}\(""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```