#### Parser Content
```Java
{
Name = suricata-network-alert
  Vendor = Suricata IDS
  Product = Suricata IDS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MM/dd/yyyy-HH:mm:ss.SSSSSS"
  Conditions = [ """[Classification:""", """ IDS-alert """]
  Fields = [
    """\s({host}[\w]+)\sIDS-alert\s({time}\d\d\/\d\d\/\d\d\d\d-\d\d:\d\d:\d\d.\d+)""",
    """\[(?:[*]+|({additional_info}[^"\]]+))\] ({alert_name}.+?)[\s\[\]*]*\[Classification:\s*({alert_type}[^\]]+)\] \[Priority:\s*({alert_severity}[^\]]+)\] \{({protocol}[^\}]+)\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)""",
  ]
}
```