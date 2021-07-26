#### Parser Content
```Java
{
Name = s-net2door-badge-access
   Vendor = Paxton
   Product = NET2DOOR
   Lms = Splunk
   DataType = "physical-access"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Conditions = [""""eventtypedescription"""", """"eventid"""", """"peripheralname""""]
   Fields = [
     """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
     """"eventtime"{0,20}:"{0,20}({time}[^"]{1,2000})"{0,20}(,|$)""",
     """"peripheralname"{0,20}:"{0,20}({location_city}.+?)\s{0,100}\-\s{0,100}({location_building}.+?)\s{0,100}(\(|\-|")""",
     """"peripheralname"{0,20}:"{0,20}([^\-]{1,2000})\-([^\-]{1,2000})\-\s{0,100}(\s{0,100}|({location_door}.+?))(\s{0,100}\-)?\s{0,100}(IN|OUT)""",
     """"eventtypedescription"{0,20}:"{0,20}({outcome}[^",]{1,2000})"{0,20}(,|$)""",
     """"eventtypedescription"{0,20}:"{0,20}([^\-]{1,2000}\-\s{0,100}({outcome_reason}[^",]{1,2000}))"{0,20}(,|$)""",
     """"username"{0,20}:"{0,20}(?:({last_name}[^,]{1,2000}),\s{0,100}({first_name}[^",]{1,2000}))"{0,20}(,|$)""",
     """"cardnumber"{0,20}:"{0,20}({badge_id}\d{1,100})""",
     """"userid"{0,20}:"{0,20}({employee_id}[^",]{1,2000})"{0,20}(,|$)""",
     """\(({direction}[^\)]{1,2000})\)"""
   ]
 }
```