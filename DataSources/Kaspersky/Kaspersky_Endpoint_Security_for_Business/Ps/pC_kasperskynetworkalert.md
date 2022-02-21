#### Parser Content
```Java
{
Name = kaspersky-network-alert
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "network-alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"GNRL_EV_OBJECT_REPORTED"""", """ WSEE|""", """ tdn="Network Threat Protection"""", """etdn="""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]{1,2000}) WSEE\|""",
    """hip="({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """hdn="({src_host}[^"]{1,2000})""",
    """etdn="({alert_name}[^"]{1,2000})""",
    """et="({alert_type}[^"]{1,2000})""",
    """({additional_info}Object detected:\s{1,200}[^:]{1,2000}?)Object name:""",
    """p2="{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000}?):({dest_port}[\d]{1,5})"""",
    """Receiver:\s{1,200}({src_ip}[A-Fa-f:\d.]{1,2000}?):({src_port}[\d]{1,5})""",
    """Protocol:\s{1,200}({protocol}\w{1,2000})"""
  ]


}
```