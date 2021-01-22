#### Parser Content
```Java
{
Name = brivo-badge-access
  Vendor = Brivo
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"occurred":""", """"siteName":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"occurred":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)Z)""",
    """"siteName":\s*"\s*({location_building}[^"]+?)\s*"""",
    """"objectName":\s*"\s*({location_door}[^"]+?)\s*"""",
    """"firstName":\s*"({first_name}[^"]+)""",
    """"lastName":\s*"({last_name}[^"]+)""",
    """"description":\s*"({outcome}[^"]+)""",
  ]
}
```