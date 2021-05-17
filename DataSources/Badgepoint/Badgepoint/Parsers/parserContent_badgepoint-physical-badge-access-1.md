#### Parser Content
```Java
{
Name = badgepoint-physical-badge-access-1
  Vendor = Badgepoint
  Product = Badgepoint
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """BadgeNumber="""", """BadgeStatus="""", """ReaderID="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]{1,2000})\s{1,100}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}""",
    """Date="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WReaderDescription="({location_full}[^"]{0,2000}?\s{0,100}({location_door}[^"\-]{1,2000}?))"""",
    """\WFacilityDescription="({location_building}[^"]{1,2000})""",
    """\WBadgeStatus="({outcome}[^"]{1,2000})""",
    """\WFacilityID="({facility_id}[^"]{1,2000})""",
    """\WReaderID="({location_door_id}[^"]{1,2000})""",
    """\WTransactionType="({transaction_type}[^"]{1,2000})""",
    """\WEmployeeNumber="({user}[^"]{1,2000})""",
    """\WBadgeNumber="({badge_id}[^"]{1,2000})""",
  ]
}
```