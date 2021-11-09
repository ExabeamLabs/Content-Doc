#### Parser Content
```Java
{
Name = counteract-network-alert
  Conditions = [ """ - DEVICE BLOCKED - """ ]
}
counteract-network-alert = {
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}\S+)\s{1,100}({alert_type}.+?)\s{1,100}-\s{1,100}({alert_name}DEVICE BLOCKED - [^\s:]{1,2000})""",
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}\S+)\s{1,100}CounterACT:\s{1,100}({alert_name}Unauthorized Host event at .+?)/({alert_type}.+?)\[\d{1,100}\]:""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """from\[({src_ip}[a-fA-F\d.:]{1,2000})\]\s{1,100}to\[({dest_ip}[a-fA-F\d.:]{1,2000})\]""",
  ]}
```