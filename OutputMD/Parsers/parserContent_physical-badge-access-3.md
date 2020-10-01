#### Parser Content
```Java
{
Name = physical-badge-access-3
  Vendor = Siemens
  Product = Siemens
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd' 'HH:mm:ss.S"
  Conditions = [ """MessageType="""", """MessageLocaleOffset="""", """CardNumber="""", """EmployeeID="""", """Direction="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """EmployeeID="({user_id}[^"]+)"""",
    """FirstName="({user_firstname}[^"]+)"""",
    """LastName="({user_lastname}[^"]+)"""",
    """CardNumber="({badge_id}[^"]+)"""",
    """MessageUTC="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d)"""",
    """MessageType="({outcome}[^"]+)"""",
    """DoorName="({location_door}[^"]+)""""
  ]
}
```