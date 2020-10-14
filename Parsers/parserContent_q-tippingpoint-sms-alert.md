#### Parser Content
```Java
{
Name = q-tippingpoint-sms-alert
  Conditions = [ """00000001-0001-0001-0001-""","\ttcp\t" ]
  Fields = ${TippingPointParserTemplates.tippingpoint-sms-alert-template.Fields} [
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+({protocol}tcp)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){4}\s+({hit_cnt}\d+)\s+""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){5}\s+({src_zone_name}[^\s]+)\s+({dest_zone_name}[^\s]+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){8}\s+({vlan_id}\d+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){9}\s+({host}[^\s]+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){11}\s+({time}\d+)""",
    """00000001-0001-0001-0001-00000\d+\s+.+?\s+\d+\s+tcp(\s+[^\s]+){12}\s+({alert_id}\d+)"""  
  ]
}
```