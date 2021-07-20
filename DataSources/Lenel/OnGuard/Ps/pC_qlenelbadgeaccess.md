#### Parser Content
```Java
{
Name = q-lenel-badge-access
    Vendor = Lenel
    Product = OnGuard
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ EVDESCR: ""Access Granted"" """, """"" EMPID: """"" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """EVENT_LOCAL_TIME:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sLASTNAME:\s{0,100}"{1,20}({last_name}[^"]{1,2000})""",
      """\sFIRSTNAME:\s{0,100}"{1,20}({first_name}[^"]{1,2000})""",
      """\sEVDESCR:\s{0,100}"{1,20}({outcome}[^"]{1,2000})""",
      """\sCARDNUM:\s{0,100}"{1,20}({badge_id}\d{1,100})""",
      """\sEMPID:\s{0,100}"{1,20}({user}[^"]{1,2000})""",
      """\sREADERDESC:\s{0,100}"{1,20}({location_full}[^"]{1,2000})"""
    ]
    DupFields = [ "location_full->location_door" ]
  }
```