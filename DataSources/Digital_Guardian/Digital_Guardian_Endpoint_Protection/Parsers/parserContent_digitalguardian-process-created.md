#### Parser Content
```Java
{
Name = digitalguardian-process-created
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "M/d/yyyy H:mm:ss a"
  Conditions = [ """ Application_Full_Name="""", """ Command_Line="""", """ Process_Created_Local_Time="""" ]
  Fields = [
    """\sAgent_Begin_UTC_Time="({time}\d{1,100}/\d{1,100}/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """<\d{1,100}>\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """\sApplication="\s{0,100}({process_name}[^"]{1,2000}?)\s{0,100}"""",
    """\sApplication_Directory="({directory}[^"]{1,2000})""",
    """\sParent_Application="\s{0,100}({parent_process_name}[^"]{1,2000}?)\s{0,100}"""",
    """\sComputer_Type="({os}[^"]{1,2000})""",
    """\sMD5_Checksum="({md5}[^"]{1,2000})""",
    """\sUser_Name="(({domain}[^"\\]{1,2000})\\+)?({user}[^\\"]{1,2000})""",
    """\sProcess_File_Size="({bytes}[^"]{1,2000})""",
    """\sCommand_Line="\s{0,100}({command_line}.+?)\s{0,100}" \#\d{1,100}""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```