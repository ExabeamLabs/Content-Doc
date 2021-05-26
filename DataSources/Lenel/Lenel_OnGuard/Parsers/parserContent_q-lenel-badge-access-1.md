#### Parser Content
```Java
{
Name = q-lenel-badge-access-1
  Vendor = Lenel
  Product = Lenel OnGuard
  Lms = QRadar
  DataType = "physical-access"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ EVDESCR: """", """ USERID: """", """ PANELNAME: """", """ READERDESC: """" ]
  Fields = [
    """EVENT_TIME_UTC:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sLASTNAME:\s{0,100}"({last_name}[^"]{1,2000})""",
    """FIRSTNAME:\s{0,100}"({first_name}[^"]{1,2000})""",
    """\sEVDESCR:\s{0,100}"({outcome}[^"]{1,2000})""",
    """\sUSERID:\s{0,100}"({badge_id}[^"]{1,2000})""",
    """\sREADERDESC:\s{0,100}"({location_door}[^"]{1,2000})""",
    """PANELNAME:\s{0,100}"({location_building}[^"]{1,2000})"""
  ]
}
```