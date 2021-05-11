#### Parser Content
```Java
{
Name = ccure-badge-access-2
    Vendor = Tyco
    Product = CCURE Building Management System
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["""objectname2""","""objectname1""","""<Card>""", """<StateCode>"""]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """"messageutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
      """"objectname1":"({last_name}[^,"]+),\s{0,100}({first_name}[^"]+)"""",
      """"objectname2":"({location_door}[^"]+)"""",
      """<Card>({badge_id}.+?)</Card>""",
      """<StateCode>({outcome}.+?)</StateCode>""",
      """<Direction.*?>({direction}.+?)</Direction>""",
    ]
  }
```