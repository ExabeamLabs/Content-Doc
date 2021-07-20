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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """EmployeeID="({user_id}[^"]{1,2000})"""",
    """FirstName="({user_firstname}[^"]{1,2000})"""",
    """LastName="({user_lastname}[^"]{1,2000})"""",
    """CardNumber="({badge_id}[^"]{1,2000})"""",
    """MessageUTC="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d)"""",
    """MessageType="({outcome}[^"]{1,2000})"""",
    """DoorName="({location_door}[^"]{1,2000})""""
  ]
}
```