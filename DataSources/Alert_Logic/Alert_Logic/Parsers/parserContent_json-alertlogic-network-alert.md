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
    """"generator":\s{0,100}\{[^\}]{0,2000}"time":\s{0,100}({time}\d{1,100})""",
    """"generator":\s{0,100}\{[^\}]{0,2000}"hostName":\s{0,100}"({host}[\w\-.]{1,2000})""",
    """"victims":\s{0,100}\["({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"attacker":\s{0,100}\[\{[^\}]{0,2000}"ip":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"incidentId":\s{0,100}"({alert_id}[^"]{1,2000})""",
    """"summary":\s{0,100}"({alert_name}[^"]{1,2000}?)\s{1,100}from [A-Fa-f:\d.]{1,2000}""",
    """"threatRating":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"incident":\s{0,100}\{.*?"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"facts_url":\s{0,100}"({additional_info}[^"]{1,2000})""",
  ]
}
```