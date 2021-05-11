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
      """exabeam_host=({host}[\w.\-]+)""",
      """"doorgroupname":"({door_group_name}[^"]+)""",
      """"eventtime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"registration no\.":({registration_no}\d{1,100})""",
      """"userid":"({user_id}[^"]+)""",
      """"event":"({outcome}[^"]+)""",
      """"issued by":"(n\/a|({user}[^"]+))""",
      """"door":"({location_door}[^"]+)""",
      """"blockinggroupname":"(n\/a|({blockinggroupname}[^"]+))""",
      """"@version":"({version}[^"]+)""",
      """"user group":"({user_group}[^"]+)"""
    ]
  }
```