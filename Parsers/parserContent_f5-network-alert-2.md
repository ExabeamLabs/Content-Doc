#### Parser Content
```Java
{
Name = f5-network-alert-2
  Vendor = F5
  Product = WAF F5
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ tmm""", """ SSL """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """\Wtmm\d+\[\d+\]:\s* \d+:\d+: ({alert_name}.+? SSL) peers ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.({src_port}\d+):({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.({dest_port}\d+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```