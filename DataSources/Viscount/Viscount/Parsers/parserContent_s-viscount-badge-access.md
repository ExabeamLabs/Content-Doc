#### Parser Content
```Java
{
Name = s-viscount-badge-access
  Vendor = Viscount
  Product = Viscount
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """, activitytype="""", """, portname="""", """, devicename="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w\.-]{1,2000})""",
    """logtime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """info="(Unknown Card|({user_fullname}[^:]{1,2000}?))(:|-)\s{0,100}({badge_id}\d{1,100})""",
    """devicename="({location_door}[^"]{1,2000})""",
    """info=".*?Area:({location_door}[^"]{1,2000})""",
    """lastname="(Unknown Card|({last_name}[^"\s]{1,2000}))""",
    """firstname="({first_name}[^"\s]{1,2000})""",
    """cardnumber="({badge_id}\d{1,100})""",
    """result="({outcome}[^"]{1,2000})""",
  ]
}
```