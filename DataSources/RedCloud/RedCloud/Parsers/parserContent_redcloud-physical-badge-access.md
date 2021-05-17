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
    Fields = [ """exabeam_host=({host}[^\s]{1,2000})""",
      """\srt=({time}\d{1,100})""",
      """\|(?:([^\|]{0,2000}\|)){4}({outcome}[^\|]{1,2000})""",
      """\scat=({category}.+?)\s{1,100}\w+=""",
      """\sduser=({last_name}[^,]{1,2000}),({first_name}.+?)\s{1,100}\w+=""",
      """\scs1=({location_building}.+?)\s{1,100}\w+=""",
      """\scs5=({location_door}.+?)\s{1,100}\w+=""",
    ]
  }
```