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
   """start=({time}\d+)""",
   """src=({src_ip}[A-Za-z\d.:]+)""",
   """cs2=({alert_name}[^,=]+?)(,|\s*\w+=)""",
   """act=({outcome}.+?)\s+\w+=""",
   """dhost=({host}.+?)\s+\w+=""",
   """request=({malware_url}.+?)\s+\w+=""",
   """dpt=({src_port}\d+)""",
   """CEF:\d+\|([^\|]+\|){4}({alert_type}[^\|]+)""",
   """CEF:\d+\|([^\|]+\|){5}({alert_severity}\d+)\|""",
   """CEF:\d+\|([^\|]+\|){3}({category}[^\|]+)""",
 ]
 
}
```