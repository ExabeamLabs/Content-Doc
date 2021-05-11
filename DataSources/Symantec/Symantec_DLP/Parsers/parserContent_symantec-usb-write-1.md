#### Parser Content
```Java
{
Name = symantec-usb-write-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """USB Transfer""", """Endpoint """ ]
  Fields = [
    """exabeam_host=({host}[^,\s]+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+?)\s{1,100}\S+\s{0,100}(?:;|,)[^;,]*(?:;|,)\s{0,100}({dest_host}[^;,]+?)\s{0,100}(?:;|,)\s{0,100}({process_name}[^;,]+?)\s{0,100}(?:;|,)[^;,]*?(?:;|,)\s{0,100}({file_name}[^;,]+?)\s{0,100}(;|,)\s{0,100}({device_type}Endpoint[^;,]+?)\s{0,100}(?:;|,)([^;,]*(?:;|,)){2}\s{0,100}(?:({domain}[^;,\\\/]+?)[\\\/]+)?({user}[^;,\\\/]*?)\s{0,100}(?:;|,)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+?)\s{1,100}\S+\s{0,100}(?:;|,)\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}(?:;|,)\s{0,100}({process_name}[^;,]+?)\s{0,100}(?:;|,)[^;,]*?(?:;|,)\s{0,100}({file_name}[^;,]+?)\s{0,100}(;|,)\s{0,100}({device_type}Endpoint[^;,]+?)\s{0,100}(?:;|,)\s{0,100}({severity}[^;,]+?)\s{0,100}(?:;|,)\s{0,100}[^;,]*(?:;|,)\s{0,100}(?:({domain}[^;,\\\/]+?)[\\\/]+)?({user}[^;,\\\/]*?)\s{0,100}(?:;|,)"""
  ]
}
```