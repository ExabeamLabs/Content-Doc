#### Parser Content
```Java
{
Name = kaspersky-es-alert-1
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ KES|""", """ p2="""", """ p5="""",""" tdn="""", """ hdn="""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]{1,2000}) KES\|""",
    """hip="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """hdn="({src_host}[^"]{1,2000})""",
    """p2="({malware_url}[^"]{1,2000})""",
    """p2="({process}({directory}(?:(\w+:)*([\\\/]{1,2000}[^\\\/"]{1,2000})+)?[\\\/]{1,2000})({process_name}[^"\\\/]{1,2000}))""",
    """etdn="({alert_name}[^"]{1,2000})""",
    """p5="({alert_name}[^"]{1,2000})""",
    """tdn="({alert_type}[^"]{1,2000})""",
    """et="({alert_type}[^"]{1,2000})""",
    """p7="(({domain}[^"\\]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
  ]
}
```