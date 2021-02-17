#### Parser Content
```Java
{
Name = json-ccure-badge-access
  Vendor = CCURE
  Product = CCURE
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
    """"doorName":\s*"({location_door}[^"]+)"""",
    """"direction":\s*"({direction}[^"]+)"""",
    """"messageDateTime":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)"""
  ]
  DupFields = [ "location_door->location_full" ]
}
```