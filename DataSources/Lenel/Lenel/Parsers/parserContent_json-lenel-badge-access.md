#### Parser Content
```Java
{
Name = json-lenel-badge-access
  Vendor = Lenel
  Product = Lenel
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"cardholder_first_name":""", """"badge_id":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)""",
    """"badge_id":({badge_id}\d+)""",
    """"cardholder_first_name":"({first_name}[^"]+)""",
    """"cardholder_last_name":"({last_name}[^"]+)""",
    """"device_name":"({location_door}[^"]+)""",
    """"description":"({outcome}[^"]+)""",
  ]
}
```