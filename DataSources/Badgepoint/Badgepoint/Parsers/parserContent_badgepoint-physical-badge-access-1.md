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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]+)\s{1,100}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}""",
    """Date="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WReaderDescription="({location_full}[^"]*?\s{0,100}({location_door}[^"\-]+?))"""",
    """\WFacilityDescription="({location_building}[^"]+)""",
    """\WBadgeStatus="({outcome}[^"]+)""",
    """\WFacilityID="({facility_id}[^"]+)""",
    """\WReaderID="({location_door_id}[^"]+)""",
    """\WTransactionType="({transaction_type}[^"]+)""",
    """\WEmployeeNumber="({user}[^"]+)""",
    """\WBadgeNumber="({badge_id}[^"]+)""",
  ]
}
```