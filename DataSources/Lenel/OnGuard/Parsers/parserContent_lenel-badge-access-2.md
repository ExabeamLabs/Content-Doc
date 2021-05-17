#### Parser Content
```Java
{
Name = lenel-badge-access-2
  Vendor = Lenel
  Product = OnGuard
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ Event_Time_CST:""", """ Emp_Id:""", """ Lnl_Emp_Id:"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Event_Time_CST:\s{0,100}"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})"{0,20}""",
    """First_Name:\s{0,100}"{0,20}(|({first_name}.+?))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
    """Last_Name:\s{0,100}"{0,20}(|({last_name}.+?))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
    """Event_Desc:\s{0,100}"{0,20}(|({outcome}.+?))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
    """Lnl_Emp_Id:\s{0,100}"{1,20}(|({badge_id}.+?))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
    """\sEmp_Id:\s{0,100}"{1,20}(|({user}.+?))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
    """Reader_Desc:\s{0,100}"{1,20}(|({location_door}[^"]{1,2000}))"{1,20}(\s{1,100}\w+:|\s{0,100}"{0,20}$)""",
  ]
}
```