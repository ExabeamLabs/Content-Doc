#### Parser Content
```Java
{
Name = cef-amag-badge-access-failed-2
  Product = Symmetry Access Control
    Conditions = [ """badge '""", """', u'Inactive', u'""" ]
  
cef-amag-badge-access = {
    Vendor = AMAG
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """badge '({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)',[^,]{1,2000}?,\su'({location_door}[^,]{0,2000}?)',\su'({outcome}[^']{0,2000}?)',\su'({badge_id}\d{1,100})',\su'({first_name}[^']{0,2000}?)',\su'({last_name}[^']{0,2000}?)',\su'({employee_id}[^']{0,2000}?)'""",
    
}
```