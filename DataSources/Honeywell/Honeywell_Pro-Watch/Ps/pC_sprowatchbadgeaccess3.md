#### Parser Content
```Java
{
Name = s-prowatch-badge-access-3
  Product = Honeywell Pro-Watch
  Conditions = [ """EventDescription="""", """EmployeeID="""", """Card#="""" ]

s-prowatch-badge-access-1 = {
    Vendor = Honeywell
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """EventDate="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\.""",
      """Card#="({badge_id}[^"]{1,2000})"""",
      """EmployeeID="({employee_id}[^"]{1,2000})"""",
      """DomainID="({domain}[^"]{1,2000})"""",
      """DoorUsed="\s{0,100}({location_door}[^"]{1,2000}?)\s{0,100}"""",
      """FirstName ="\s{0,100}({first_name}[^"]{1,2000}?)\s{0,100}"""",
      """LastName ="\s{0,100}({last_name}[^"]{1,2000}?)\s{0,100}"""",
      """Department="\s{0,100}({location_building}[^"]{1,2000}?)\s{0,100}"""",
      """EventDescription="({outcome}[^"]{1,2000})"""",
    
}
```