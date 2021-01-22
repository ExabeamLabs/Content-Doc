#### Parser Content
```Java
{
Name = ccure-badge-access
  Vendor = CCURE
  Product = CCURE
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"messagetype":"Card""", """"statecode":"""", """"primaryobjectname":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"messageutc":"({time}[^"]+)""",
    """"statecode":"({event_name}[^"]+)""",
    """"messagetype":"({outcome}[^"]+)""",
    """"primaryobjectname":"*(null|({last_name}[^",]+?)\s*,\s*({first_name}[^",]+?))\s*"""",
    """"secondaryobjectname":"*(null|({location_door}[^"]+))""",
  ]
}
```