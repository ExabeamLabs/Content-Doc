#### Parser Content
```Java
{
Name = physical-badge-access-2
    Vendor = Badge
  Product = Badge
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
    Conditions = [ """, ID="""", """, PersonName="""", """, DoorName="""", """, CardNumber="""" ]
    Fields = [
      """\sController="({host}[^"]{1,2000})""",
      """\sTimeStamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
      """\sID="({employee_id}[^"]{1,2000})""",
      """\sPersonName="({last_name}[^"_]{1,2000}?)\s{0,100}_({first_name}[^"_]{1,2000}?)\s{0,100}(_({middle_initial}[^"_\s]{1,2000}?))?\s{0,100}"""",
      """\sAreaName="({location_building}[^"]{1,2000}?)(_({direction}In|Out))?"""",
      """\sDoorName="({location_door}[^"]{1,2000})""",
      """\sCardNumber="({badge_id}\d{1,100})""",
      """\sEventType="({outcome}[^"]{1,2000})""",
    ]
  }
```