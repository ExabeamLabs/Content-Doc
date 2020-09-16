#### Parser Content
```Java
{
Name = cef-ccure-badge-access-2
    Vendor = CCURE
    Product = CCURE
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = ["""CEF:""", """|Software House|CCure Badge|"""]
    Fields = [
      """\srt=({time}\d+)""",
      """\sduser=\s*({last_name}[^,]+?)\s*,\s*({first_name}.+?)(\s+\w+=|\s*$)""",
      """\scs3=({location_door}.+?)(\s+\w+=|\s*$)""",
      """\|CCure Badge\|[^\|]*\|({outcome}.+?)\|"""
      """exabeam_host=({host}[\w.\-]+)""",
    ]
  }
```