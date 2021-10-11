#### Parser Content
```Java
{
Name = rs2-badge-failed-physical-access-1
  DataType = "failed-physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Access denied]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[({outcome}[^>]{1,2000}?)\]{1,2000}><\/DESCNAME>"""
  ]
}
badge-physical-access = {
    Vendor = RS2 Technologies
    Product = RS2 Technologies
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """<ACTIVITYID>({event_code}\d{1,100})<\/ACTIVITYID>""",
      """<DESCNAME><!\[CDATA\[({event_name}[^\]]{1,2000})\]{1,2000}><\/DESCNAME>""",
      """<CDT>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\.\d{1,100}<\/CDT>""",
      """<PERSONNAME><!\[CDATA\[({user_fullname}({last_name}[^,]{1,2000}),\s({first_name}[^\]]{1,2000}))\]{1,2000}><\/PERSONNAME>""",
      """<PERSONID>\s{0,100}({badge_id}[^>]{1,2000}?)\s{0,100}<\/PERSONID>""",
      """<RDRNAME><!\[CDATA\[({location_door}[^\]]{1,2000})\]{1,2000}><\/RDRNAME>"""
    ]

```