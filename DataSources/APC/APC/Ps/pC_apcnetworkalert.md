#### Parser Content
```Java
{
Name = apc-network-alert
  Vendor = APC
  Product = APC
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Detected an unauthorized user attempting""", """ from """ ]
  Fields = [
    """(<\d{1,100}>)?(\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d)\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}(System:\s{0,100})?({alert_name}Detected an ({alert_type}unauthorized user) attempting to access .*? from ({src_ip}[a-fA-F\d.:]{1,2000}))\.?\s{1,100}""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  ]
  DupFields = [ "host->dest_host" ]


}
```