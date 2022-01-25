#### Parser Content
```Java
{
Name = gcp-ids-network-alert
  Vendor = Google
  Product = Cloud IDS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """ destinationServiceName =Google Cloud Platform (GCP) """, """"type":"ids.googleapis.com""", """"type":"vulnerability"""", """"source_ip_address":""", """"alert_severity":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"timestamp":({time}\d{1,100})\,""",
    """"source_ip_address":"({src_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"source_port":"({src_port}\d{1,100})"""",
    """"destination_ip_address":"({dest_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"destination_port":"({dest_port}\d{1,100})"""",
    """"name":"({alert_name}[^"]{1,2000})"""",
    """"type":"({alert_type}vulnerability)"""",
    """"alert_severity":"({alert_severity}[^"]{1,2000})"""",
    """"ip_protocol":"({protocol}[^"]{1,2000})"""",
    """"details":"({additional_info}[^"]{1,2000})""""
  ]


}
```