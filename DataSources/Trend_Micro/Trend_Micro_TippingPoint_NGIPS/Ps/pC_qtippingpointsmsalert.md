#### Parser Content
```Java
{
Name = q-tippingpoint-sms-alert
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """00000001-0001-0001-0001-""","\ttcp\t" ]
  Fields = ${TippingPointParserTemplates.tippingpoint-sms-alert-template.Fields} [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}({protocol}tcp)""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){4}\s{1,100}({hit_cnt}\d{1,100})\s{1,100}""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){5}\s{1,100}({src_zone_name}[^\s]{1,2000})\s{1,100}({dest_zone_name}[^\s]{1,2000})""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){8}\s{1,100}({vlan_id}\d{1,100})""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){9}\s{1,100}({host}[^\s]{1,2000})""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){11}\s{1,100}({time}\d{1,100})""",
    """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}tcp(\s{1,100}[^\s]{1,2000}){12}\s{1,100}({alert_id}\d{1,100})"""  
  ]

tippingpoint-sms-alert-template = {
    Vendor = Trend Micro
    Product = Trend Micro TippingPoint NGIPS
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Fields = [
          """({alert_severity}\d)\s{1,100}([\w\d-])+\s00000001-0001-0001-0001-0000""",
          """\s{1,100}({event_code}[^\s]{1,2000})\s{1,100}00000001-0001-0001-0001-00000""",
          """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}({alert_name}.+?)\s{1,100}\d{1,100}\s{1,100}""",
          """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}[^\s]{1,2000}\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}({src_port}\d{1,100})""",
          """00000001-0001-0001-0001-00000\d{1,100}\s{1,100}.+?\s{1,100}\d{1,100}\s{1,100}([^\s]{1,2000}\s{1,100}){3}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}({dest_port}\d{1,100})""",
    ]
    SOAR {
      IncidentType = "generic"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
      NameTemplate = """TippingPoint Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]},
        {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address"]},
      ]
    }
  
}
```