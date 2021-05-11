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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s{1,100}({dest_host}[\w.\-]+)""",
    """\suinfo="({user}[^\\"]+)\\+[^"]+?({domain}[^,"\\]+?),[^,"\\]*?"""",
    """\ssproc="({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?)"""",
    """\sact="({accesses}[^"]+)"""",
    """\sgp="({file_parent}[^"]+)"""",
    """\sfilePath="\\+({file_name}[^"\\]+)"""",
    """\sdenyStr="({action}[^"]+)""""
    """({alert_name}DENIED)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```