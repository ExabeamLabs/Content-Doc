#### Parser Content
```Java
{
Name = gallagher-physical-access
  DataType = "physical-access"
  Conditions = [ """"gallagher"""", """"Door Access Granted"""" ]

gallagher-physical-access = {
    Vendor = Gallagher
    Product = Access Control
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"gallagher","({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)","\d{0,100}","({outcome}[^"]{1,2000})","({location_door}[^"]{1,2000})","(|({first_name}[^"]{1,2000}))","(|({last_name}[^"]{1,2000}))","({additional_info}[^"]{1,2000}?\s(to|into)\s({location_building}[^"]{1,2000}?))\.?(\s{0,100}Reason:[^"]{0,2000})?","({employee_id}[^"]{1,2000})","[^"]{0,2000}","({badge_id}[^"]{1,2000})","({user}[^"]{1,2000})""""
    ]
    DupFields = [ "outcome->event_name" 
}
```