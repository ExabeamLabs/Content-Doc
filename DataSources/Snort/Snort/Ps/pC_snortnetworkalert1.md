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
    """\s({host}[\w\-.]{1,2000})\s{1,100}snort\[""",
    """\[SNORTIDS\[[^"]{0,2000}?({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\S*\s{1,100}\d{1,100}\s{1,100}\[[^\]]{0,2000}\]\s{1,100}({alert_name}[^\|]{1,2000}?)\s{0,100}\|+\s{0,100}({alert_type}[^\|]{0,2000}?)\s{0,100}\|+\s{0,100}({alert_severity}\d{1,100})\s{1,100}({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}[^\|]{0,2000}?\|+[^\|]{0,2000}?\|+\s{0,100}({additional_info}[^|]{0,2000}?)\s{0,100}\|\|"""
  ]
}
```