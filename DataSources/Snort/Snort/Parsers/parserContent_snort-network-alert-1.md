#### Parser Content
```Java
{
Name = snort-network-alert-1
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ snort[""", """[SNORTIDS[""", """ || """ ]
  Fields = [
    """\s({host}[\w\-.]+)\s+snort\[""",
    """\[SNORTIDS\[.*?({time}\d+-\d+-\d+\s+\d+:\d+:\d+)\S*\s+\d+\s+\[[^\]]*\]\s+({alert_name}[^\|]+?)\s*\|+\s*({alert_type}[^\|]*?)\s*\|+\s*({alert_severity}\d+)\s+({dest_ip}[A-Fa-f:\d.]+)\s+({src_ip}[A-Fa-f:\d.]+)\s+[^\|]*?\|+[^\|]*?\|+\s*({additional_info}.*?)\s*\|\|""",
  ]
}
```