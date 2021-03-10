#### Parser Content
```Java
{
Name = apc-network-alert
  Vendor = APC
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Detected an unauthorized user attempting""", """ from """ ]
  Fields = [
    """(<\d+>)?(\w+\s+\d+\s+\d\d:\d\d:\d\d)\s+({host}[\w.\-]+)\s+(System:\s*)?({alert_name}Detected an ({alert_type}unauthorized user) attempting to access .*? from ({src_ip}[a-fA-F\d.:]+))\.?\s+""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```