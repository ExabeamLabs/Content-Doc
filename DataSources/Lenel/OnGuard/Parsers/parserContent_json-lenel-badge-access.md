#### Parser Content
```Java
{
Name = json-lenel-badge-access
  Vendor = Lenel
  Product = OnGuard
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"cardholder_first_name":""", """"badge_id":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)""",
    """"badge_id":({badge_id}\d{1,100})""",
    """"cardholder_first_name":"({first_name}[^"]{1,2000})""",
    """"cardholder_last_name":"({last_name}[^"]{1,2000})""",
    """"device_name":"({location_door}[^"]{1,2000})""",
    """"description":"({outcome}[^"]{1,2000})""",
  ]
}
```