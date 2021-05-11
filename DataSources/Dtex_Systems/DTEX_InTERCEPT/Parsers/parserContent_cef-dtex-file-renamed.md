#### Parser Content
```Java
{
Name = cef-dtex-file-renamed
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|FileRenamed|""" ]
  Fields = [
    """\Wstart=({time}\d{1,100})""",
    """\|Dtex\|([^\|]*\|){2}(FileSystemActivity\|)?({accesses}[^\|]+)\|""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\WProcess_Name=(?:\s{0,100}|({process_name}.+?)\s{1,100})(\w+=|$)""",
    """\WProcess_Directory=(?:\s{0,100}|({directory}.+?)\s{1,100})(\w+=|$)""",
    """\WDestination_File_Extension=({file_ext}[^\s]+)\s""",
    """\WDestination_File_Name=(?:\s{0,100}|({file_name}.+?)\s{1,100})(\w+=|$)""",
    """\WDestination_File_Directory=(?:\s{0,100}|({file_parent}.+?)\s{1,100})(\w+=|$)""",
    """\|Dtex\|([^\|]*\|){3}.*?➔\s{0,100}({file_path}.+?)\s\(.*?\)\|""",
    """Destination_File_Details=\{.*?"Type":\s{0,100}"({file_type}[^"]+)"\}""",
    """\WSource_File_Directory=(?:\s{0,100}|({src_file_dir}.+?)\s{1,100})(\w+=|$)""",
    """\WSource_File_Name=(?:\s{0,100}|({src_file_name}.+?)\s{1,100})(\w+=|$)""",
    """\WDestination_File_Size=({bytes}\d{1,100})""",
    """"ImageDetails":\s{0,100}\{.*?"ProductName":\s{0,100}"({app}[^"]+)""""
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```