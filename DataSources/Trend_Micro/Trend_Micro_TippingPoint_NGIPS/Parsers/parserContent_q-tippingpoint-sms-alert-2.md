#### Parser Content
```Java
{
Name = q-tippingpoint-sms-alert-2
  Conditions = [ """00000001-0001-0001-0001-""","\tip\t" ]
  Fields = ${TippingPointParserTemplates.tippingpoint-sms-alert-template.Fields} [
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+({protocol}ip)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){4}\s+({hit_cnt}\d+)\s+""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){5}\s+({src_zone_name}[^\s]+)\s+({dest_zone_name}[^\s]+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){8}\s+({vlan_id}\d+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){9}\s+({host}[^\s]+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){11}\s+({time}\d+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+ip(\s+[^\s]+){12}\s+({alert_id}\d+)"""  
  ]
}
tippingpoint-sms-alert-template = {
    Vendor = Trend Micro
    Product = Trend Micro TippingPoint NGIPS
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Fields = [
          """({alert_severity}\d)\s+([\w\d-])+\s00000001-0001-0001-0001-0000""",
          """\s+({event_code}[^\s]+)\s+00000001-0001-0001-0001-00000""",
          """00000001-0001-0001-0001-00000\d+\s+({alert_name}.+?)\s+\d+\s+""",
          """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+[^\s]+\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+({src_port}\d+)""",
          """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+([^\s]+\s+){3}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+({dest_port}\d+)""",
    ]

```