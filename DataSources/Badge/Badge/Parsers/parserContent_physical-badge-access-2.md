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
      """\sController="({host}[^"]+)""",
      """\sTimeStamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
      """\sID="({employee_id}[^"]+)""",
      """\sPersonName="({last_name}[^"_]+?)\s{0,100}_({first_name}[^"_]+?)\s{0,100}(_({middle_initial}[^"_\s]+?))?\s{0,100}"""",
      """\sAreaName="({location_building}[^"]+?)(_({direction}In|Out))?"""",
      """\sDoorName="({location_door}[^"]+)""",
      """\sCardNumber="({badge_id}\d{1,100})""",
      """\sEventType="({outcome}[^"]+)""",
    ]
  }
```