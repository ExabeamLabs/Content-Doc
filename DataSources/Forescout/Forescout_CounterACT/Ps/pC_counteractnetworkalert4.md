#### Parser Content
```Java
{
Name = counteract-network-alert-4
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, Rule:""", """, Details:""", """ Source:""", """]: NAC Policy Log:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(\w{1,100}\s\d\d\s\d\d:\d\d:\d\d)\s{1,100}(({host_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({host}[\w\-.]{1,2000}))""",
    """Source:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """Rule:\s{0,100}(|({alert_name}Policy\s{1,100}"{0,20}[^"]{1,2000}?\s{0,100}"{0,20}))\s{0,100

}
```