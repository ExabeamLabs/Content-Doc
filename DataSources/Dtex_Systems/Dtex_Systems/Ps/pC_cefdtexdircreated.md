#### Parser Content
```Java
{
Name = cef-dtex-dir-created
  Product = DTEX InTERCEPT
  Conditions = [ "CEF:", """|Dtex|""", """|DirectoryCreated|""" ]
}
cef-dtex-file-operations = {
    Vendor = Dtex Systems
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Fields = [
      """\Wstart=({time}\d{1,100})""",
      """\|Dtex\|([^\|]{0,2000}\|){2}(FileSystemActivity\|)?({accesses}[^\|]{1,2000})\|""",
      """\|Dtex\|([^\|]{0,2000}\|){3}({file_path}[^\|]{1,2000}?)\s\(.*?\)\|""",
      """\WDevice_Name=(({domain}[^\\=]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
      """"ImageDetails":\s{0,100}\{.*?"ProductName":\s{0,100}"\s{0,100}({app}[^"]{1,2000})"""",
      """\WProcess_Directory=(?:\s{0,100}|({directory}.+?)\s{1,100})(\w+=|$)""",
      """\WProcess_Name=(?:\s{0,100}|({process_name}.+?)\s{1,100})(\w+=|$)""",
      """Source_File_Details=\{.*?"Type":\s{0,100}"({file_type}[^"]{1,2000})"\}""",
      """\WSource_File_Directory=(?:\s{0,100}|({file_parent}.+?)\s{1,100})(\w+=|$)""",
      """\WSource_File_Extension=({file_ext}[^\s]{1,2000})\s""",
      """\WSource_File_Name=(?:\s{0,100}|({file_name}.+?)\s{1,100})(\w+=|$)""",
      """\WSource_File_Size=({bytes}\d{1,100})""",
      """\WUser_Name=(({domain}[^\\=]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s"""
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]}
```