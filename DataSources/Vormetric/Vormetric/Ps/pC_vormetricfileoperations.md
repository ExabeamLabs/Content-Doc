#### Parser Content
```Java
{
Name = vormetric-file-operations
  Vendor = Vormetric
  Product = Vormetric
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ gp=""", """ denyStr="""", """ uinfo="""", """ showStr="""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s{1,100}({dest_host}[\w.\-]{1,2000})""",
    """\suinfo="({user}[^\\"]{1,2000})\\+[^"]{1,2000}?({domain}[^,"\\]{1,2000}?),[^,"\\]{0,2000}?"""",
    """\ssproc="({process}({directory}[^"]{0,2000}?)(\\+({process_name}[^"\\]{1,2000}?))?)"""",
    """\sact="({accesses}[^"]{1,2000})"""",
    """\sgp="({file_parent}[^"]{1,2000})"""",
    """\sfilePath="\\+({file_name}[^"\\]{1,2000})"""",
    """\sdenyStr="({action}[^"]{1,2000})""""
    """({alert_name}DENIED)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```