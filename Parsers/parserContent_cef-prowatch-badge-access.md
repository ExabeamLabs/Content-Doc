#### Parser Content
```Java
{
Name = cef-prowatch-badge-access
    Vendor = Honeywell
  Product = Honeywell Pro-Watch
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat =  "epoch"
    Conditions = [ """|ProWatch|Access System|""", """cs6Label=Location""", """ cs4=""" ]
    Fields = [
      """exabeam_host=([^=]*@\s*)?({host}[^\s]+)""",
      """\srt=({time}\d+)""",
      """\|ProWatch\|Access System\|([^\|]*\|){2}({outcome}[^\|]+)\|""",
      """\sduser=\s*({last_name}[^,]+?)\s*,\s*({first_name}.+?)\s+\w+=""",
      """\scs6=\s*(Empty|({location_door}\S.*?))\s+\w+=""",
    ]
  }
```