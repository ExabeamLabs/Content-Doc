#### Parser Content
```Java
{
Name = s-pan-networks-file-activity
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "cloud_app_instance", """"activity_monitoring"""", ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
    """exabeam_host=({host}[\w\-.]+)""",
    """\Wuser"?\s{0,100}(=|:)\s{0,100}"({user_email}[^"]+)"""",
    """\Wcloud_app_instance"?\s{0,100}(=|:)\s{0,100}"({app}[^"]+)"""",
    """\Wsource_ip"?\s{0,100}(=|:)\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Witem_name"?\s{0,100}(=|:)\s{0,100}"({file_name}[^"]+?(\.\s{0,100}({file_ext}[^\."]+?))?)"""",
    """\Waction"?\s{0,100}(=|:)\s{0,100}"({accesses}[^"]+)"""",
    """\Witem_type"?\s{0,100}(=|:)\s{0,100}"({file_type}[^"]+)"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```