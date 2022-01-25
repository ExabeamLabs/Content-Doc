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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"messageutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
      """"objectname1":"({last_name}[^,"]{1,2000}),\s{0,100}({first_name}[^"]{1,2000})"""",
      """"objectname2":"({location_door}[^"]{1,2000})"""",
      """<Card>({badge_id}.+?)</Card>""",
      """<StateCode>({outcome}.+?)</StateCode>""",
      """<Direction.*?>({direction}.+?)</Direction>""",
    ]
  }
```