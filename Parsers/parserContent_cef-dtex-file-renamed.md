#### Parser Content
```Java
{
Name = cef-dtex-file-renamed
  Vendor = Dtex
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|FileRenamed|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\|Dtex\|([^\|]*\|){2}(FileSystemActivity\|)?({accesses}[^\|]+)\|""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\WProcess_Name=(?:\s*|({process_name}.+?)\s+)(\w+=|$)""",
    """\WProcess_Directory=(?:\s*|({directory}.+?)\s+)(\w+=|$)""",
    """\WDestination_File_Extension=({file_ext}[^\s]+)\s""",
    """\WDestination_File_Name=(?:\s*|({file_name}.+?)\s+)(\w+=|$)""",
    """\WDestination_File_Directory=(?:\s*|({file_parent}.+?)\s+)(\w+=|$)""",
    """\|Dtex\|([^\|]*\|){3}.*?➔\s*({file_path}.+?)\s\(.*?\)\|""",
    """Destination_File_Details=\{.*?"Type":\s*"({file_type}[^"]+)"\}""",
    """\WSource_File_Directory=(?:\s*|({src_file_dir}.+?)\s+)(\w+=|$)""",
    """\WSource_File_Name=(?:\s*|({src_file_name}.+?)\s+)(\w+=|$)""",
    """\WDestination_File_Size=({bytes}\d+)""",
    """"ImageDetails":\s*\{.*?"ProductName":\s*"({app}[^"]+)""""
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```