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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """LoggedTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """DoorName="({location_door}[^"]+)""",
    """UserID="({badge_id}[^"]+)""",
    """UserName="({user}[^"\s]+)"""",
    """UserName="({user_fullname}[^"\s,]+\s+[^",]+)"""",
    """EventName="({event_name}[^"]+?)\s*"""",
    """ControllerName="({device_name}[^"]+)""",
  ]
}
```