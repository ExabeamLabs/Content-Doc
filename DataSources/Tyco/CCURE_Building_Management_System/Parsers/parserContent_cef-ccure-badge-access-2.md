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
      """\sduser=\s{0,100}({last_name}[^,]+?)\s{0,100}
```