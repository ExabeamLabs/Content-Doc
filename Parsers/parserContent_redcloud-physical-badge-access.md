#### Parser Content
```Java
{
Name = redcloud-physical-badge-access
    Vendor = RedCloud
  Product = RedCloud
    Lms = Direct
    DataType = "physical-access"
    TimeFormat =  "epoch"
    Conditions = [ """CEF:""","""|RedCloud|Enterprise|""", """Credential""" ]
    Fields = [ """exabeam_host=({host}[^\s]+)""",
      """\srt=({time}\d+)""",
      """\|(?:([^\|]*\|)){4}({outcome}[^\|]+)""",
      """\scat=({category}.+?)\s+\w+=""",
      """\sduser=({last_name}[^,]+),({first_name}.+?)\s+\w+=""",
      """\scs1=({location_building}.+?)\s+\w+=""",
      """\scs5=({location_door}.+?)\s+\w+=""",
    ]
  }
```