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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]+) KES\|""",
    """hip="({src_ip}[A-Fa-f:\d.]+)""",
    """hdn="({src_host}[^"]+)""",
    """p2="({malware_url}[^"]+)""",
    """p2="({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/"]+)+)?[\\\/]+)({process_name}[^"\\\/]+))""",
    """etdn="({alert_name}[^"]+)""",
    """p5="({alert_name}[^"]+)""",
    """tdn="({alert_type}[^"]+)""",
    """et="({alert_type}[^"]+)""",
    """p7="(({domain}[^"\\]+)\\+)?({user}[^\\\s"]+)""",
  ]
}
```