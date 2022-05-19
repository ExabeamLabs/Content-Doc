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
   """src=({src_ip}[A-Za-z\d.:]{1,2000})""",
   """cs2=({alert_name}[^,=]{1,2000}?)(,|\s{0,100}\w+=)""",
   """act=({outcome}.+?)\s{1,100}\w+=""",
   """dhost=({host}.+?)\s{1,100}\w+=""",
   """request=({malware_url}.+?)\s{1,100}\w+=""",
   """dpt=({src_port}\d{1,100})""",
   """CEF:\d{1,100}\|([^\|]{1,2000}\|){4}({alert_type}[^\|]{1,2000})""",
   """CEF:\d{1,100}\|([^\|]{1,2000}\|){5}({alert_severity}\d{1,100})\|""",
   """CEF:\d{1,100}\|([^\|]{1,2000}\|){3}({category}[^\|]{1,2000})""",
 ]
 


}
```