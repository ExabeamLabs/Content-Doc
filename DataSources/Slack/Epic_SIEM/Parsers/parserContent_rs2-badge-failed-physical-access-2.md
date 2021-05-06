#### Parser Content
```Java
{
Name = rs2-badge-failed-physical-access-2
  DataType = "failed-physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Elevator access denied]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[Elevator ({outcome}[^>]+?)\]+><\/DESCNAME>"""
  ]
}
badge-physical-access = {
    Vendor = RS2 Technologies
    Product = RS2 Technologies
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """<ACTIVITYID>({event_code}\d+)<\/ACTIVITYID>""",
      """<DESCNAME><!\[CDATA\[({event_name}[^\]]+)\]+><\/DESCNAME>""",
      """<CDT>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\.\d+<\/CDT>""",
      """<PERSONNAME><!\[CDATA\[({user_fullname}({last_name}[^,]+),\s({first_name}[^\]]+))\]+><\/PERSONNAME>""",
      """<PERSONID>\s*({badge_id}[^>]+?)\s*<\/PERSONID>""",
      """<RDRNAME><!\[CDATA\[({location_door}[^\]]+)\]+><\/RDRNAME>"""
    ]

```