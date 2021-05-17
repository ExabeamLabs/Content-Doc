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
    """hostname:\s{0,100}"({host}[^"]{1,2000})""",
    """nId:\s{0,100}"({alert_id}[^"]{1,2000})""",
    """EventDisplayName:\s{0,100}"({alert_name}[^"]{1,2000})""",
    """wstrPar5:\s{0,100}"(null|({alert_name}[^"]{1,2000}))""",
    """wstrPar2:\s{0,100}"(null|({malware_url}[^"]{1,2000}))""",
    """wstrPar8:\s{0,100}"(null|({alert_severity}[^"]{1,2000}))""",
    """User:\s{1,100}(({domain}[^\\]{0,2000})\\+)?({user}[^\\\s]{1,2000})\s{0,100}\(""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```