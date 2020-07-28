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
    """\Wuser"?\s*(=|:)\s*"({user_email}[^"]+)"""",
    """\Wcloud_app_instance"?\s*(=|:)\s*"({app}[^"]+)"""",
    """\Wsource_ip"?\s*(=|:)\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Witem_name"?\s*(=|:)\s*"({file_name}[^"]+?(\.\s*({file_ext}[^\."]+?))?)"""",
    """\Waction"?\s*(=|:)\s*"({accesses}[^"]+)"""",
    """\Witem_type"?\s*(=|:)\s*"({file_type}[^"]+)"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```