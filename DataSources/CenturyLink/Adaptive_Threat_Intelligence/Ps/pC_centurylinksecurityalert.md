#### Parser Content
```Java
{
Name = centurylink-security-alert
  Vendor = CenturyLink
  Product = Adaptive Threat Intelligence
  Lms=Direct
  TimeFormat = "epoch"
  DataType = "security-alert"
  Conditions=["""ati-threatflow""", """"event_type":"threatflow"""", """"dstAS":"""]
  Fields=[
    """"timestamp":({time}\d{1,100})""",
    """"dstThreat":"({alert_type}[^"]{1,2000})""",
    """"srcThreat":"({alert_name}[^"]{1,2000})""",
    """"agent":"({host}[^"]{1,2000})"""",
    """"srcAddr":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """"dstAddr":"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """"srcPort":({src_port}\d{1,100})""",
    """"dstPort":({dest_port}\d{1,100})""",
    """"protocol":({protocol}\d{1,100})""",
    """"event_type":"({log_type}[^"]{1,2000})"""",
    """"dstScore":"(0|({alert_severity}[^"]{1,2000}))"""",
  ]
  DupFields = ["alert-severity" -> "priority"]


}
```