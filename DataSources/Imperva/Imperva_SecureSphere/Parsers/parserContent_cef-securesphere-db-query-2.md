#### Parser Content
```Java
{
Name = cef-securesphere-db-query-2
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|SecureSphere|""", """|Audit CounterBreach for Database""", """|Informative|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wsuser=({user}[^\\\s]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsntdom=({domain}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wcat=({db_operation}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({db_query}.+?)\s{1,100}(\w+=|$)""",
    """\Wdproc=({database_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wcn2=({response_size}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```