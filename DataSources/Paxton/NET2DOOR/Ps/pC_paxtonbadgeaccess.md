#### Parser Content
```Java
{
Name = paxton-badge-access
  Vendor = Paxton
  Product = NET2DOOR
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "dd-MM-yyyy HH:mm:ss"
  Conditions = [ """ PaxtonNet2 """, """CardNumber=""", """EventTypeDescription="""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}) PaxtonNet2""",
    """EventTime="({time}\d{1,100}-\d\d-\d\d\d\d \d\d:\d\d:\d\d)""",
    """UserID="({employee_id}[^"]{1,2000})"""",
    """FirstName="({first_name}[^"]{1,2000})"""",
    """Surname="({last_name}[^"]{1,2000})"""",
    """CardNumber="({badge_id}[^"]{1,2000})"""",
    """PeripheralName="({location_door}[^"\(]{1,2000}?) \(({direction}[^\)"]{1,2000})\)"""",
    """EventTypeDescription="({outcome}[^"\-]{1,2000}?) - ({auth_method}[^"]{1,2000})"""",
  ]
}
```