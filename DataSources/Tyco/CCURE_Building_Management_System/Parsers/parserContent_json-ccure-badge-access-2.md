#### Parser Content
```Java
{
Name = json-ccure-badge-access-2
    Vendor = Tyco
    Product = CCURE Building Management System
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = [""""badge_id":""", """"user":""", """"location_city":""", """"location_building":""", """"location_door":""", """"location_full":""", """"outcome":""", """"transaction_time_gmt":""", """"direction":"""]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"transaction_time_gmt":({time}\d{1,100})""",
      """"user":\s{0,100}"({user}[^"]{1,2000})"""
      """"location_door":({location_door}\d{1,100})""",
      """"location_building":\s{0,100}"({location_building}[^"]{1,2000})""",
      """"location_city":\s{0,100}"({location_city}[^"]{1,2000})""",
      """"location_full":\s{0,100}"({location_full}[^"]{1,2000})""",
      """"outcome":\s{0,100}"({outcome}[^"]{1,2000})""",
      """"badge_id":({badge_id}\d{1,100})""",
      """"direction":\s{0,100}"({direction}[^"]{1,2000})"""",
    ]
  }
```