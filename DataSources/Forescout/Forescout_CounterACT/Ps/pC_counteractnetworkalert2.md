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
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}Forescout""",
    """Source:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """Rule:\s{0,100}(|({alert_name}Policy\s{1,100}"[^"]{1,2000}?\s{0,100}"))\s{0,100}
```