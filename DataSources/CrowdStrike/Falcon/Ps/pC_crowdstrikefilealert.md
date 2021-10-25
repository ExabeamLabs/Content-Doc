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
    """"timestamp":"({time}\d{1,100})""",
    """"event_simpleName":"({alert_name}[^"]{1,2000})""",
    """"aip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"aid":"({aid}[^"]{1,2000})""",
    """"event_platform":"({os}[^"]{1,2000})""",
    """"ConfigStateHash":"({old_hash}[^"]{1,2000})""",
    """"SHA256HashData":"({new_hash}[^"]{1,2000})""",
    """"ImageFileName":"({file_path}[^"]{1,2000})""",
    """"ImageFileName":"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}?\.({file_ext}[^\\\.\s"]{1,2000})?)"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```