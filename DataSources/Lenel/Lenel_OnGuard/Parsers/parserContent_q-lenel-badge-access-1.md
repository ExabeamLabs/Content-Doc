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
    """exabeam_host=({host}[\w.\-]+)""",
    """\sLASTNAME:\s{0,100}"({last_name}[^"]+)""",
    """FIRSTNAME:\s{0,100}"({first_name}[^"]+)""",
    """\sEVDESCR:\s{0,100}"({outcome}[^"]+)""",
    """\sUSERID:\s{0,100}"({badge_id}[^"]+)""",
    """\sREADERDESC:\s{0,100}"({location_door}[^"]+)""",
    """PANELNAME:\s{0,100}"({location_building}[^"]+)"""
  ]
}
```