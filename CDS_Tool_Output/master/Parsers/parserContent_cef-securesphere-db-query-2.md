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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+)""",
    """\Wsuser=({user}[^\\\s]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsntdom=({domain}[^\s]+)\s+(\w+=|$)""",
    """\Wcat=({db_operation}.+?)\s+(\w+=|$)""",
    """\Wmsg=({db_query}.+?)\s+(\w+=|$)""",
    """\Wdproc=({database_name}.+?)\s+(\w+=|$)""",
    """\Wcn2=({response_size}.+?)\s+(\w+=|$)""",
  ]
}
```