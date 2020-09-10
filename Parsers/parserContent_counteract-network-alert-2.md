#### Parser Content
```Java
{
Name = counteract-network-alert-2
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ forescout Forescout """, """, Rule:""", """, Details:""", """ Source:""" ]
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s+({host}[\w\-.]+)\s+Forescout""",
    """Source:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """Rule:\s*(|({alert_name}Policy\s+"[^"]+?\s*"))\s*,""",
    """Details:\s*({additional_info}.+?)\s*(\.\s+\w+:|$)""",
    """Reason:\s*(|({outcome}[^\.:]+?))\s*\.""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```