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
      """exabeam_host=([^=]*@\s{0,100})?({host}[^\s]+)""",
      """\srt=({time}\d{1,100})""",
      """\|ProWatch\|Access System\|([^\|]*\|){2}({outcome}[^\|]+)\|""",
      """\sduser=\s{0,100}({last_name}[^,]+?)\s{0,100}
```