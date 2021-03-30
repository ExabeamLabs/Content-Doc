#### Parser Content
```Java
{
Name = lenel-badge-access
  Vendor = Lenel
  Product = Lenel
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ EVENT_TIME_UTC:""", """ CARDNUM:""", """ EMPID:""" ]
  Fields = [
    """({host}\S+)\s+INFO\s+id:\s""",
    """\sEVENT_TIME_UTC:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sFIRSTNAME:\s*(|({first_name}.+?))(\s+\w+:|\s*$)""",
    """\sLASTNAME:\s*(|({last_name}.+?))(\s+\w+:|\s*$)""",
    """\sEVDESCR:\s*(|({outcome}.+?))(\s+\w+:|\s*$)""",
    """\sCARDNUM:\s*(|({badge_id}.+?))(\s+\w+:|\s*$)""",
    """\sEMPID:\s*(|({employee_id}.+?))(\s+\w+:|\s*$)""",
    """\sREADERDESC:\s*(|({location_full}.+?))(\s+\w+:|\s*$)""",
    """\sSSNO:\s*(|NULL|({ssno}.+?))(\s+\w+:|\s*$)""",
  ]
    DupFields = [ "location_full->location_door" ]
}
```