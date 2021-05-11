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
    """"serverName":\s{0,100}"({host}[^"]+)"""",
    """"firstName":\s{0,100}"({first_name}[^"]+)"""",
    """"lastName":\s{0,100}"({last_name}[^"]+)"""",
    """"ntid":\s{0,100}"({user}[^"]+)"""",
    """"doorName":\s{0,100}"({location_door}[^"]+?)\s{0,100}"""",
    """"direction":\s{0,100}"({direction}[^"]+)"""",
    """"messageDateTime":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"admitReject":\s{0,100}"({outcome}[^"]+)""""
  ]
  DupFields = [ "location_door->location_full" ]
}
```