#### Parser Content
```Java
{
Name = snort-network-alert-3
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[Classification:""","""[Priority:""","""] [""" ]
  Fields = [
    """\[Classification:\s{1,100}({alert_type}[^\]]{1,2000})""",
    """\[Priority:\s{1,100}({alert_severity}[^\]]{1,2000})""",
    """\d{1,100}\]\s({alert_name}.+?)\s{0,100}(\s\S{1,100}\s)?\[Classification""",
    """Priority:[^:]{1,2000}?\{(PROTO:)?({protocol}[^\}]{1,2000})\}""",
    """({src_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]+:[a-fA-F\d:]+))(:({src_port}\d{1,100}))?\s{0,100}->\s{0,100}({dest_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]+:[a-fA-F\d:]+))(:({dest_port}\d{1,100}))?"""
  ]


}
```