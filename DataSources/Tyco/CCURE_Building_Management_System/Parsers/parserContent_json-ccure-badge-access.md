#### Parser Content
```Java
{
Name = json-ccure-badge-access
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"ntid":""", """"personType":""", """"doorName":""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """"serverName":\s*"({host}[^"]+)"""",
    """"firstName":\s*"({first_name}[^"]+)"""",
    """"lastName":\s*"({last_name}[^"]+)"""",
    """"ntid":\s*"({user}[^"]+)"""",
    """"doorName":\s*"({location_door}[^"]+?)\s*"""",
    """"direction":\s*"({direction}[^"]+)"""",
    """"messageDateTime":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"admitReject":\s*"({outcome}[^"]+)""""
  ]
  DupFields = [ "location_door->location_full" ]
}
```