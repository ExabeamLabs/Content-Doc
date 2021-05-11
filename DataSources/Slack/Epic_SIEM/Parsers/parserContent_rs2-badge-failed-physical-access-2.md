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
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """<ACTIVITYID>({event_code}\d{1,100})<\/ACTIVITYID>""",
      """<DESCNAME><!\[CDATA\[({event_name}[^\]]+)\]+><\/DESCNAME>""",
      """<CDT>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\.\d{1,100}<\/CDT>""",
      """<PERSONNAME><!\[CDATA\[({user_fullname}({last_name}[^,]+),\s({first_name}[^\]]+))\]+><\/PERSONNAME>""",
      """<PERSONID>\s{0,100}({badge_id}[^>]+?)\s{0,100}<\/PERSONID>""",
      """<RDRNAME><!\[CDATA\[({location_door}[^\]]+)\]+><\/RDRNAME>"""
    ]

```