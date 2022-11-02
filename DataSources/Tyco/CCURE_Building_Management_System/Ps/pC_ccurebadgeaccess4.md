#### Parser Content
```Java
{
Name = ccure-badge-access-4
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """vendor_action=""","""door_name="""","""reason_code="""" ]
  Fields = [
    """message_time="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """door_name="({location_door}[^"]{1,2000})"""",
    """card_number="({badge_id}[^"]{1,2000})"""",
    """employee_id="({employee_id}[^"]{1,2000})"""",
    """last_name="({last_name}[^"]{1,2000})"""",
    """first_name="({first_name}[^"]{1,2000})"""",
    """reason_code="({action}[^"]{1,2000})"""",
    """vendor_action="({outcome}[^"]{1,2000})"""",
    """description="({additional_info}[^"]{1,2000})"""",
    """user="({user}[^"]{1,2000})""""
  ]


}
```