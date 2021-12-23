#### Parser Content
```Java
{
Name = illumio-network-connection-1
  Vendor = Illumio
  Product = Illumio
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ illumio_pce""", """"un":"""", """"src_hostname":"""", """"pce_fqdn":"""" ]
  Fields = [
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}illumio_pce""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """pid=({pid}\d{1,100})""",
    """sev=({alert_severity}[^=]{1,2000}?)\s{1,100}\w{1,2000}=""",
    """"src_ip":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"dst_ip":"({dest_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"dst_port":({dest_port}\d{1,100})""",
    """"proto":({protocol}\d{1,100})""",
    """"src_hostname":"({src_host}[^"]{1,2000})"""",
    """"dst_hostname":"({dest_host}[^"]{1,2000})"""",
    """"un":"(({domain}[^\\"]{1,2000})\\{1,20})?({user}[^"]{1,2000})"""",
    """"fqdn":"({web_domain}[^"]{1,2000})"""",
    """"pn":"({process_name}[^"]{1,2000})"""",
    """"dir":"({direction}[^"]{1,2000})"""",
    """"pd":({outcome}\d{1,100})""",
    """"dst_href":"({uri_path}[^"]{1,2000})""""
  ]


}
```