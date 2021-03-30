#### Parser Content
```Java
{
Name = crowdstrike-file-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Skyformation|""", """"event_simpleName":"QuarantinedFileState"""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"timestamp":"({time}\d+)""",
    """"event_simpleName":"({alert_name}[^"]+)""",
    """"aip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"aid":"({aid}[^"]+)""",
    """"event_platform":"({os}[^"]+)""",
    """"ConfigStateHash":"({old_hash}[^"]+)""",
    """"SHA256HashData":"({new_hash}[^"]+)""",
    """"ImageFileName":"({file_path}[^"]+)""",
    """"ImageFileName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+?\.({file_ext}[^\\\.\s"]+)?)"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```