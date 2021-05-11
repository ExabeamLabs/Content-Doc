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
    """\s({host}[\w\-.]+)\s{1,100}snort\[""",
    """\[SNORTIDS\[.*?({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\S*\s{1,100}\d{1,100}\s{1,100}\[[^\]]*\]\s{1,100}({alert_name}[^\|]+?)\s{0,100}\|+\s{0,100}({alert_type}[^\|]*?)\s{0,100}\|+\s{0,100}({alert_severity}\d{1,100})\s{1,100}({dest_ip}[A-Fa-f:\d.]+)\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}[^\|]*?\|+[^\|]*?\|+\s{0,100}({additional_info}.*?)\s{0,100}\|\|""",
  ]
}
```