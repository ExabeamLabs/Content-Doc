#### Parser Content
```Java
{
Name = counteract-network-alert-3
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, Rule:""", """, Details:""", """ Source:""", """Main Appliance[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s+\d+ \d+:\d+:\d+)\s+({host}[^\s]+)\s+Main Appliance\[""",
    """Source:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """Rule:\s*(|({alert_name}Policy\s+"*[^"]+?\s*"*))\s*,""",
    """Details:\s*({additional_info}.+?)\s*(\.\s+\w+:|$)""",
    """Reason:\s*(|({outcome}[^\.:]+?))\s*\.""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```