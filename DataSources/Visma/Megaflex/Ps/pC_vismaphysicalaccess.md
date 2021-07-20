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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"decision":"({outcome}[^"]{1,2000})"""",
    """"eventTime":({time}[^,]{1,2000}),""",
    """"person".*?"id":({user_id}\d{1,100})""",
    """"firstName":"({first_name}[^"]{1,2000})"""",
    """"lastName":"({last_name}[^"]{1,2000})"""",
    """"token".*?"id":({badge_id}\d{1,100})""",
    """"destinationArea".*?"type":"({location_area}[^"]{1,2000})"""",
    """"destinationArea".*?"id":({location_door_id}[^,]{1,2000}),""",
    """"destinationArea".*?"name":"({location_full}[^"]{1,2000})"""",
    """"sourceArea".*?"type":"({source_location_area}[^"]{1,2000})"""",
    """"sourceArea".*?"id":({source_location_door_id}[^,]{1,2000}),""",
    """"sourceArea".*?"name":"({source_location_full}[^"]{1,2000})"""",
  ]
}
```