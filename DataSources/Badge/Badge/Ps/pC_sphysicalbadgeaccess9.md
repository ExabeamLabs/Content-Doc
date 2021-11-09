#### Parser Content
```Java
{
Name = s-physical-badge-access-9
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
    Conditions = [ """, EmpID="""", """, LastAccess="""", """, Panel="""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """\sEmpID="({employee_id}\d{1,100})""",
      """\sLastAccess="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
      """\sSite="({location_city}[^"]{1,2000}?)\s{0,100}"""",
      """\sPanel="({location_building}[^"]{1,2000}?)\s{0,100}"""",
      """\sReader="({location_door}[^"]{1,2000}?)\s{0,100}"""",
    ]
  }
}
```