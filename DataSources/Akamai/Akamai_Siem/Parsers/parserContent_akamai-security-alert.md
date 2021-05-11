#### Parser Content
```Java
{
Name = akamai-security-alert
 Product = Akamai Siem
 Vendor = Akamai
 Lms = Direct
 DataType = "alert"
 TimeFormat = "epoch"
 Conditions = [ """CEF:""", """Akamai|akamai_siem""", """requestMethod=""", """ cs2Label=Rule""" ]
 Fields =[
   """start=({time}\d{1,100})""",
   """src=({src_ip}[A-Za-z\d.:]+)""",
   """cs2=({alert_name}[^,=]+?)(,|\s{0,100}\w+=)""",
   """act=({outcome}.+?)\s{1,100}\w+=""",
   """dhost=({host}.+?)\s{1,100}\w+=""",
   """request=({malware_url}.+?)\s{1,100}\w+=""",
   """dpt=({src_port}\d{1,100})""",
   """CEF:\d{1,100}\|([^\|]+\|){4}({alert_type}[^\|]+)""",
   """CEF:\d{1,100}\|([^\|]+\|){5}({alert_severity}\d{1,100})\|""",
   """CEF:\d{1,100}\|([^\|]+\|){3}({category}[^\|]+)""",
 ]
 
}
```