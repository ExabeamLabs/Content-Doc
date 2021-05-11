#### Parser Content
```Java
{
Name = brivo-badge-access
  Vendor = Brivo
  Product = Brivo
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"occurred":""", """"siteName":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"occurred":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,100})Z)""",
    """"siteName":\s{0,100}"\s{0,100}({location_building}[^"]+?)\s{0,100}"""",
    """"objectName":\s{0,100}"\s{0,100}({location_door}[^"]+?)\s{0,100}"""",
    """"firstName":\s{0,100}"({first_name}[^"]+)""",
    """"lastName":\s{0,100}"({last_name}[^"]+)""",
    """"description":\s{0,100}"({outcome}[^"]+)""",
  ]
}
```