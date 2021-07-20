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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """"serverName":\s{0,100}"({host}[^"]{1,2000})"""",
    """"firstName":\s{0,100}"({first_name}[^"]{1,2000})"""",
    """"lastName":\s{0,100}"({last_name}[^"]{1,2000})"""",
    """"ntid":\s{0,100}"({user}[^"]{1,2000})"""",
    """"doorName":\s{0,100}"({location_door}[^"]{1,2000}?)\s{0,100}"""",
    """"direction":\s{0,100}"({direction}[^"]{1,2000})"""",
    """"messageDateTime":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"admitReject":\s{0,100}"({outcome}[^"]{1,2000})""""
  ]
  DupFields = [ "location_door->location_full" ]
}
```