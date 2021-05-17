#### Parser Content
```Java
{
Name = timelox-badge-access
    Vendor = TimeLox
  Product = TimeLox
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"eventtime":"""", """"doorgroupname":"""", """"issued by":""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"doorgroupname":"({door_group_name}[^"]{1,2000})""",
      """"eventtime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"registration no\.":({registration_no}\d{1,100})""",
      """"userid":"({user_id}[^"]{1,2000})""",
      """"event":"({outcome}[^"]{1,2000})""",
      """"issued by":"(n\/a|({user}[^"]{1,2000}))""",
      """"door":"({location_door}[^"]{1,2000})""",
      """"blockinggroupname":"(n\/a|({blockinggroupname}[^"]{1,2000}))""",
      """"@version":"({version}[^"]{1,2000})""",
      """"user group":"({user_group}[^"]{1,2000})"""
    ]
  }
```