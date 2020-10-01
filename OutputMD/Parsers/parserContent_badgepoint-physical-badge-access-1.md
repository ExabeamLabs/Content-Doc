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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+""",
    """Date="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\WReaderDescription="({location_full}[^"]*?\s*({location_door}[^"\-]+?))"""",
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