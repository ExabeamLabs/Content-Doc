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
    """({host}[\w\-.]+) PaxtonNet2""",
    """EventTime="({time}\d+-\d\d-\d\d\d\d \d\d:\d\d:\d\d)""",
    """UserID="({employee_id}[^"]+)"""",
    """FirstName="({first_name}[^"]+)"""",
    """Surname="({last_name}[^"]+)"""",
    """CardNumber="({badge_id}[^"]+)"""",
    """PeripheralName="({location_door}[^"\(]+?) \(({direction}[^\)"]+)\)"""",
    """EventTypeDescription="({outcome}[^"\-]+?) - ({auth_method}[^"]+)"""",
  ]
}
```