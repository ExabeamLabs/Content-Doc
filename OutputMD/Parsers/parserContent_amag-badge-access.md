#### Parser Content
```Java
{
Name = amag-badge-access
  Vendor = AMAG
  Product = Symmetry Access Control
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"access_badge"""", """"txnconditionname":"""", """"cardnumber":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"datetimeoftxn":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"txnconditionname":"({outcome}[^"]+)""",
    """"wherename":"({location_door}[^"]+)""",
    """"firstname":"({user_firstname}[^"]+)""",
    """"lastname":"({user_lastname}[^"]+)""",
    """"cardnumber":({badge_id}\d+)""",
    """"db_name":"({direction}[^"]+)""",
    """"db_ip":"({dest_ip}[a-fA-F\d.:]+)""",
  ]
}
```