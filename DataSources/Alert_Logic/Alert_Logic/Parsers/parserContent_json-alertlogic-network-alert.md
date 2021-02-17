#### Parser Content
```Java
{
Name = json-alertlogic-network-alert
  Vendor = Alert Logic
  Product = Alert Logic
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"source_keyword":""", """"IDS"""", """"account_deployments":""", """"associatedEventCount":""" ]
  Fields = [
    """"generator":\s*\{[^\}]*"time":\s*({time}\d+)""",
    """"generator":\s*\{[^\}]*"hostName":\s*"({host}[\w\-.]+)""",
    """"victims":\s*\["({dest_ip}[A-Fa-f:\d.]+)""",
    """"attacker":\s*\[\{[^\}]*"ip":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"incidentId":\s*"({alert_id}[^"]+)""",
    """"summary":\s*"({alert_name}[^"]+?)\s+from [A-Fa-f:\d.]+""",
    """"threatRating":\s*"({alert_severity}[^"]+)""",
    """"incident":\s*\{.*?"type":\s*"({alert_type}[^"]+)""",
    """"facts_url":\s*"({additional_info}[^"]+)""",
  ]
}
```