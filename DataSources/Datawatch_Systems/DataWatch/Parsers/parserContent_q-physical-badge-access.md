#### Parser Content
```Java
{
Name = q-physical-badge-access
    Vendor = Datawatch Systems
  Product = DataWatch
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat =  "MM/dd/yy HH:mm:ss"
    Conditions = [ """DataWatch""","""Badge Access""" ]
    Fields = [ """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
      """\|({time}\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\|""",
      """(?:([^\|]{0,2000}\|)){4}({outcome}.+?)(:.+?)?\s{1,100}At\s{1,100}({location_door}[^\|]{1,2000})\|""",
      """(?:([^\|]{0,2000}\|)){5}({last_name}[^,]{1,2000}),({first_name}[^\|]{1,2000})\|""",
      """(?:([^\|]{0,2000}\|)){6}({badge_id}[^\|]{1,2000})\|""",
    ]
  }
```