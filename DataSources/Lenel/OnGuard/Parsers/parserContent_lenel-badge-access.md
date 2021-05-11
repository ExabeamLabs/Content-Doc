#### Parser Content
```Java
{
Name = lenel-badge-access
  Vendor = Lenel
  Product = OnGuard
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ EVENT_TIME_UTC:""", """ CARDNUM:""", """ EMPID:""" ]
  Fields = [
    """({host}\S+)\s{1,100}INFO\s{1,100}id:\s""",
    """\sEVENT_TIME_UTC:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sFIRSTNAME:\s{0,100}(|({first_name}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sLASTNAME:\s{0,100}(|({last_name}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sEVDESCR:\s{0,100}(|({outcome}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sCARDNUM:\s{0,100}(|({badge_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sEMPID:\s{0,100}(|({employee_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sREADERDESC:\s{0,100}(|({location_full}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sSSNO:\s{0,100}(|NULL|({ssno}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
  ]
    DupFields = [ "location_full->location_door" ]
}
```