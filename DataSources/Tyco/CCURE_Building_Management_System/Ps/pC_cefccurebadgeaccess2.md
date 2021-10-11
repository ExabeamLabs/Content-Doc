#### Parser Content
```Java
{
Name = cef-ccure-badge-access-2
    Vendor = Tyco
    Product = CCURE Building Management System
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = ["""CEF:""", """|Software House|CCure Badge|"""]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sduser=\s{0,100}({last_name}[^,]{1,2000}?)\s{0,100},\s{0,100}({first_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\scs3=({location_door}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\|CCure Badge\|[^\|]{0,2000}\|({outcome}.+?)\|"""
      """exabeam_host=({host}[\w.\-]{1,2000})""",
    ]
  }
```