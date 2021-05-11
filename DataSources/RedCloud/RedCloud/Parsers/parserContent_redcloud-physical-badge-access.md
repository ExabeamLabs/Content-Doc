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
      """\srt=({time}\d{1,100})""",
      """\|(?:([^\|]*\|)){4}({outcome}[^\|]+)""",
      """\scat=({category}.+?)\s{1,100}\w+=""",
      """\sduser=({last_name}[^,]+),({first_name}.+?)\s{1,100}\w+=""",
      """\scs1=({location_building}.+?)\s{1,100}\w+=""",
      """\scs5=({location_door}.+?)\s{1,100}\w+=""",
    ]
  }
```