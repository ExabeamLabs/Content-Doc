#### Parser Content
```Java
{
Name = rs2-badge-access
  Vendor = RS2 Technologies
  Product = RS2 Technologies
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """CardNumber=""", """SiteName=""", """EventLocation=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sEventDate="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
    """\sSiteName="({location_building}[^"]{1,2000})""",
    """\sEventLocation="({location_door}[^"]{1,2000})""",
    """\sEventDescription="({outcome}[^"]{1,2000})""",
    """\sEID="({user}[^"]{1,2000})""",
    """\sCardNumber="({badge_id}[^"]{1,2000})""",
    """\sFirstName="\s{0,100}({first_name}[^"]{1,2000}?)\s{0,100}"""",
    """\sLastName="\s{0,100}({last_name}[^"]{1,2000}?)\s{0,100}"""",
  ]
}
```