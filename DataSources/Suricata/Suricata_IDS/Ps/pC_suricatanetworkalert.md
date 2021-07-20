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
    """\s({host}[\w]{1,2000})\sIDS-alert\s({time}\d\d\/\d\d\/\d\d\d\d-\d\d:\d\d:\d\d.\d{1,100})""",
    """\[(?:[*]{1,2000}|({additional_info}[^"\]]{1,2000}))\] ({alert_name}.+?)[\s\[\]]{0,2000}\[Classification:\s{0,100}({alert_type}[^\]]{1,2000})\] \[Priority:\s{0,100}({alert_severity}[^\]]{1,2000})\] \{({protocol}[^\}]{1,2000})\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})""",
  ]
}
```