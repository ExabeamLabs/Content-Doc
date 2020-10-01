#### Parser Content
```Java
{
Name = gm-print-activity
 Vendor = HP
 Product = HP LaserJet Printer
 Lms = Direct
 DataType = "print-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = ["""LaserJet""", """job_lab_ntusername"""]
 Fields = [ 
   """@timestamp"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
   """host"+:"+({host}[^"]+)""",
   """job_lab_ntusername"+:"+(?:Unspecified|({user}[^"]+))""",
   """job_lab_documentname"+:"+(?:Unspecified|({object}[^"]+))""",
   """job_qty_size"+:({bytes}\d+)""",
   """job_qty_printedpages"+:({num_pages}\d+)""",
   """printer_lab_localname"+:"+({printer_name}[^"]+)""", 
   """printer_lab_ipaddress"+:["\s]*({src_ip}[a-fA-F\d.:]+)""",
   """port"*:({src_port}[\d]+)""",
   """job_lab_ntusermachine"+:"+(?:Unspecified|({src_host}[^"]+))""",
 ]
}
```