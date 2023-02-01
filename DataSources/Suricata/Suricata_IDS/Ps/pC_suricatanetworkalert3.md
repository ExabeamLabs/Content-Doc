#### Parser Content
```Java
{
Name = suricata-network-alert-3
  Vendor = Suricata
  Product = Suricata IDS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"alert"""", """"event_source":"suricata"""", """"event_type":"alert""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d[\+\-]\d\d\d\d)""",
    """"signature":"({alert_name}[^"]{1,200})""",
    """"severity":({alert_severity}\d)""",
    """"src_ip":"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"event_type":"({alert_type}[^"]{1,2000})""",
    """"dest_ip":"({dest_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"dest_port":({dest_port}\d{1,5})""",
    """"src_port":({src_port}\d{1,5})""",
    """"signature_id":({alert_id}\d{1,2000})""",
    """"proto":"({protocol}\w{1,2000})""",
    """"payload":"({additional_info}[^"]{1,2000})""",
    """"sensor_hostname":"({src_host}[^"]{1,2000})"""
  ]


}
```