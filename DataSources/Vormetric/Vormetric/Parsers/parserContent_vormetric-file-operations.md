#### Parser Content
```Java
{
Name = vormetric-file-operations
  Vendor = Vormetric
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ gp=""", """ denyStr="PERMIT"""", """ uinfo="""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s+({dest_host}[\w.\-]+)""",
    """\suinfo="({user}[^\\"]+)\\+[^"]+?({domain}[^,"\\]+?),[^,"\\]*?"""",
    """\ssproc="({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?)"""",
    """\sact="({accesses}[^"]+)"""",
    """\sgp="({file_parent}[^"]+)"""",
    """\sfilePath="\\+({file_name}[^"\\]+)""""
  ]
  DupFields = [ "directory->process_directory" ]
}
```