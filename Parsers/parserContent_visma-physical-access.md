#### Parser Content
```Java
{
Name = visma-physical-access
  Vendor = Visma
  Product = Megaflex
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """"decision":"""", """accessPoint""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"decision":"({outcome}[^"]+)"""",
    """"eventTime":({time}[^,]+),""",
    """"person".*?"id":({user_id}\d+)""",
    """"firstName":"({first_name}[^"]+)"""",
    """"lastName":"({last_name}[^"]+)"""",
    """"token".*?"id":({badge_id}\d+)""",
    """"destinationArea".*?"type":"({location_area}[^"]+)"""",
    """"destinationArea".*?"id":({location_door_id}[^,]+),""",
    """"destinationArea".*?"name":"({location_full}[^"]+)"""",
    """"sourceArea".*?"type":"({source_location_area}[^"]+)"""",
    """"sourceArea".*?"id":({source_location_door_id}[^,]+),""",
    """"sourceArea".*?"name":"({source_location_full}[^"]+)"""",
  ]
}
```