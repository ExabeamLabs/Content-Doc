#### Parser Content
```Java
{
Name = json-ccure-badge-access-2
    Vendor = CCURE
    Product = CCURE
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = [""""badge_id":""", """"user":""", """"location_city":""", """"location_building":""", """"location_door":""", """"location_full":""", """"outcome":""", """"transaction_time_gmt":""", """"direction":"""]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """"transaction_time_gmt":({time}\d+)""",
      """"user":\s*"({user}[^"]+)"""
      """"location_door":({location_door}\d+)""",
      """"location_building":\s*"({location_building}[^"]+)""",
      """"location_city":\s*"({location_city}[^"]+)""",
      """"location_full":\s*"({location_full}[^"]+)""",
      """"outcome":\s*"({outcome}[^"]+)""",
      """"badge_id":({badge_id}\d+)""",
      """"direction":\s*"({direction}[^"]+)"""",
    ]
  }
```