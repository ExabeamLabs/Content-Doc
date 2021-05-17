#### Parser Content
```Java
{
Name = s-onguard-physical-badge-access-2
  Vendor = Lenel
  Product = OnGuard
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"readerdesc"""", """"segmentname"""", """"panelname"""", """"badgekey"""", """"event_time_utc"""", """"changedate"""" ]
  Fields = [
    """"host"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"""",
    """"event_time_utc"{1,20}:"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)""",
    """"lastname"{1,20}:\s{0,100}"{1,20}({last_name}[^"]{1,2000})"""",
    """"firstname"{1,20}:\s{0,100}"{1,20}({first_name}[^"]{1,2000})"""",
    """"cardnum"{1,20}:({card_num}\d{1,100})""",
    """"readerdesc"{1,20}:\s{0,100}"{1,20}({location_door}[^"]{1,2000})"""",
    """"devid"{1,20}:({devid}\d{1,100})""",
    """"panelname"{1,20}:\s{0,100}"{1,20}({location_building}[^"]{1,2000})"""",
    """"emp_id"{1,20}:({employee_id}\d{1,100})""",
    """"badgekey":({badge_id}\d{1,100})"""
  ]
}
```