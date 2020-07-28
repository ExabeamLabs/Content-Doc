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
    """\sAgent_Begin_UTC_Time="({time}\d+/\d+/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))""",
    """<\d+>\w+ \d+ \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """\sApplication="\s*({process_name}[^"]+?)\s*"""",
    """\sApplication_Directory="({directory}[^"]+)""",
    """\sParent_Application="\s*({parent_process_name}[^"]+?)\s*"""",
    """\sComputer_Type="({os}[^"]+)""",
    """\sMD5_Checksum="({md5}[^"]+)""",
    """\sUser_Name="(({domain}[^"\\]+)\\+)?({user}[^\\"]+)""",
    """\sProcess_File_Size="({bytes}[^"]+)""",
    """\sCommand_Line="\s*({command_line}.+?)\s*" \#\d+""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```