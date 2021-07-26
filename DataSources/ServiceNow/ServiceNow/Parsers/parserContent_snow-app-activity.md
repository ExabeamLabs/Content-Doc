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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """,sys_created_on="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,dv_sys_class_name="({activity}[^"]{1,2000})""",
    """,dv_number="({object}[^"]{1,2000})""",
    """,incident_state="({resource}[^"]{1,2000})""",
    """,dv_assignment_group="({additional_info}[^"]{1,2000})""",
    """,sys_created_by="({user}[^"]{1,2000})""",
    """,dv_assigned_to="(|({user}[^"]{1,2000}))""",
    """({app}ServiceNow)""",
  ]
}
```