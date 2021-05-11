#### Parser Content
```Java
{
Name = snow-app-activity
  Vendor = ServiceNow
  Product = ServiceNow
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,sys_created_on="""", """,dv_sys_class_name="""", """,dv_number="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """,sys_created_on="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,dv_sys_class_name="({activity}[^"]+)""",
    """,dv_number="({object}[^"]+)""",
    """,incident_state="({resource}[^"]+)""",
    """,dv_assignment_group="({additional_info}[^"]+)""",
    """,sys_created_by="({user}[^"]+)""",
    """,dv_assigned_to="(|({user}[^"]+))""",
    """({app}ServiceNow)""",
  ]
}
```