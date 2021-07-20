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
      """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """\srt=({time}\d{1,100})""",
      """\|ProWatch\|Access System\|([^\|]{0,2000}\|){2}({outcome}[^\|]{1,2000})\|""",
      """\sduser=\s{0,100}({last_name}[^,]{1,2000}?)\s{0,100}
```