#### Parser Content
```Java
{
Name = suricata-network-alert
  Vendor = Suricata
  Product = Suricata IDS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MM/dd/yyyy-HH:mm:ss.SSSSSS"
  Conditions = [ """[Classification:""", """ IDS-alert """]
  Fields = [
    """\s({host}[\w]+)\sIDS-alert\s({time}\d\d\/\d\d\/\d\d\d\d-\d\d:\d\d:\d\d.\d{1,100})""",
    """\[(?:[*]+|({additional_info}[^"\]]+))\] ({alert_name}.+?)[\s\[\]*]*\[Classification:\s{0,100}({alert_type}[^\]]+)\] \[Priority:\s{0,100}({alert_severity}[^\]]+)\] \{({protocol}[^\}]+)\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})""",
  ]
}
```