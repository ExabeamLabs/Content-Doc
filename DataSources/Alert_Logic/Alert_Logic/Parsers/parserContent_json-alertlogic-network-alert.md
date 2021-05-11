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
    """"generator":\s{0,100}\{[^\}]*"time":\s{0,100}({time}\d{1,100})""",
    """"generator":\s{0,100}\{[^\}]*"hostName":\s{0,100}"({host}[\w\-.]+)""",
    """"victims":\s{0,100}\["({dest_ip}[A-Fa-f:\d.]+)""",
    """"attacker":\s{0,100}\[\{[^\}]*"ip":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)""",
    """"incidentId":\s{0,100}"({alert_id}[^"]+)""",
    """"summary":\s{0,100}"({alert_name}[^"]+?)\s{1,100}from [A-Fa-f:\d.]+""",
    """"threatRating":\s{0,100}"({alert_severity}[^"]+)""",
    """"incident":\s{0,100}\{.*?"type":\s{0,100}"({alert_type}[^"]+)""",
    """"facts_url":\s{0,100}"({additional_info}[^"]+)""",
  ]
}
```