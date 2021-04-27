#### Parser Content
```Java
{
Name = lenel-badge-access-2
  Vendor = Lenel
  Product = Lenel
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ Event_Time_CST:""", """ Emp_Id:""", """ Lnl_Emp_Id:"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """Event_Time_CST:\s*"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)"*""",
    """First_Name:\s*"*(|({first_name}.+?))"+(\s+\w+:|\s*"*$)""",
    """Last_Name:\s*"*(|({last_name}.+?))"+(\s+\w+:|\s*"*$)""",
    """Event_Desc:\s*"*(|({outcome}.+?))"+(\s+\w+:|\s*"*$)""",
    """Lnl_Emp_Id:\s*"+(|({badge_id}.+?))"+(\s+\w+:|\s*"*$)""",
    """\sEmp_Id:\s*"+(|({user}.+?))"+(\s+\w+:|\s*"*$)""",
    """Reader_Desc:\s*"+(|({location_door}[^"]+))"+(\s+\w+:|\s*"*$)""",
  ]
}
```