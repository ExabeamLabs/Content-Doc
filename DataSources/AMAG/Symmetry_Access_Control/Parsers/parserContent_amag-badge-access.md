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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"datetimeoftxn":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"txnconditionname":"({outcome}[^"]{1,2000})""",
    """"wherename":"({location_door}[^"]{1,2000})""",
    """"firstname":"({user_firstname}[^"]{1,2000})""",
    """"lastname":"({user_lastname}[^"]{1,2000})""",
    """"cardnumber":({badge_id}\d{1,100})""",
    """"db_name":"({direction}[^"]{1,2000})""",
    """"db_ip":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
```