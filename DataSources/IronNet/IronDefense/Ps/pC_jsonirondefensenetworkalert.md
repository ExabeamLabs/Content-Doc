#### Parser Content
```Java
{
Name = json-irondefense-network-alert
  Vendor = IronNet
  Product = IronDefense
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"app":"irondefense"""", """"type":"event"""", """"alert_status":"""", """"severity":"""", """"alert_aggregation_criteria":""""  ] 
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"start_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"subject":"({alert_name}[^",]{1,2000})"""",
    """"src_category":"({alert_type}[^",]{1,2000})"""",
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"alert_status":"({alert_status}[^",]{1,2000})"""",
    """"src_ip":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"dst_ip":"({dest_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"dst_port":({dest_port}\d{1,100})""",
    """"bytes_out":({bytes_out}\d{1,100})""",
    """"body":"({additional_info}[^",]{1,2000})""""
  ]


}
```