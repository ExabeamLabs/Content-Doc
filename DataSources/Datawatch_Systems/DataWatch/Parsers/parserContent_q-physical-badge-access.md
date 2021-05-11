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
    Fields = [ """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
      """\|({time}\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\|""",
      """(?:([^\|]*\|)){4}({outcome}.+?)(:.+?)?\s{1,100}At\s{1,100}({location_door}[^\|]+)\|""",
      """(?:([^\|]*\|)){5}({last_name}[^,]+),({first_name}[^\|]+)\|""",
      """(?:([^\|]*\|)){6}({badge_id}[^\|]+)\|""",
    ]
  }
```