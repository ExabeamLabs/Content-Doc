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
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}[^\s]+)\s{1,100}Main Appliance\[""",
    """Source:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
    """Rule:\s{0,100}(|({alert_name}Policy\s{1,100}"{0,20}[^"]+?\s{0,100}"{0,20}))\s{0,100}
```