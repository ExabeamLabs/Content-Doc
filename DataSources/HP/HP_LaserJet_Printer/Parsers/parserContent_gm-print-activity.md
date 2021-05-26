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
   """@timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
   """host"{1,20}:"{1,20}({host}[^"]{1,2000})""",
   """job_lab_ntusername"{1,20}:"{1,20}(?:Unspecified|({user}[^"]{1,2000}))""",
   """job_lab_documentname"{1,20}:"{1,20}(?:Unspecified|({object}[^"]{1,2000}))""",
   """job_qty_size"{1,20}:({bytes}\d{1,100})""",
   """job_qty_printedpages"{1,20}:({num_pages}\d{1,100})""",
   """printer_lab_localname"{1,20}:"{1,20}({printer_name}[^"]{1,2000})""", 
   """printer_lab_ipaddress"{1,20}:["\s]{0,2000}({src_ip}[a-fA-F\d.:]{1,2000})""",
   """port"{0,20}:({src_port}[\d]{1,2000})""",
   """job_lab_ntusermachine"{1,20}:"{1,20}(?:Unspecified|({src_host}[^"]{1,2000}))""",
 ]
}
```