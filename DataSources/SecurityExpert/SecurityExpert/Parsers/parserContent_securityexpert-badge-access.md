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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """LoggedTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """DoorName="({location_door}[^"]+)""",
    """UserID="({badge_id}[^"]+)""",
    """UserName="({user}[^"\s]+)"""",
    """UserName="({user_fullname}[^"\s,]+\s{1,100}[^",]+)"""",
    """EventName="({event_name}[^"]+?)\s{0,100}"""",
    """ControllerName="({device_name}[^"]+)""",
  ]
}
```