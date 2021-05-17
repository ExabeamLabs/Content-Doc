#### Parser Content
```Java
{
Name = securityexpert-badge-access
  Vendor = SecurityExpert
  Product = SecurityExpert
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """UserID="""", """EventID=""", """EventName="""", """LoggedTime="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """LoggedTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """DoorName="({location_door}[^"]{1,2000})""",
    """UserID="({badge_id}[^"]{1,2000})""",
    """UserName="({user}[^"\s]{1,2000})"""",
    """UserName="({user_fullname}[^"\s,]{1,2000}\s{1,100}[^",]{1,2000})"""",
    """EventName="({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """ControllerName="({device_name}[^"]{1,2000})""",
  ]
}
```