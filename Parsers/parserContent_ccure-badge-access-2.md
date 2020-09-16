#### Parser Content
```Java
{
Name = ccure-badge-access-2
    Vendor = CCURE
    Product = CCURE
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["""objectname2""","""objectname1""","""<Card>""", """<StateCode>"""]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """"messageutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
      """"objectname1":"({last_name}[^,"]+),\s*({first_name}[^"]+)"""",
      """"objectname2":"({location_door}[^"]+)"""",
      """<Card>({badge_id}.+?)</Card>""",
      """<StateCode>({outcome}.+?)</StateCode>""",
      """<Direction.*?>({direction}.+?)</Direction>""",
    ]
  }
```