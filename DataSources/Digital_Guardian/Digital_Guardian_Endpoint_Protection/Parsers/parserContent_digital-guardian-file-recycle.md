#### Parser Content
```Java
{
Name = digital-guardian-file-recycle
  Product = Digital Guardian Endpoint Protection
  DataType = "file-delete"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="17"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
digital-guardian-activity = {
  Vendor = Digital Guardian
  Product = Digital Guardian
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """Agent_Local_Time="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s\d{1,100}:\d{1,100}:\d{1,100}\s(AM|PM|am|pm))""",
    """\w+\s\d\d\s\d\d:\d\d:\d\d\s{0,100}({host}[\w\-.]+)\s\w+=""",
    """\sComputer_Name="(({domain}[^\\]+)?\\?({src_host}[^"]+))""",
    """\sUser_Name="(({domain}[^\\]+)?\\?({user}[^"]+))""",
    """\sSource_Directory="({src_file_dir}[^=]+?)\s{0,100}"\s{0,100}\w+=""",
    """\sDestination_Directory="({file_parent}[^=]+?)\s{0,100}"\s{0,100}\w+=""",
    """\sDestination_File="({file_name}[^=]+?)\s{0,100}"\s{0,100}\w+=""",
    """\sOperation="({event_code}\d{1,100})""",
    """\sApplication="({process_name}[^"]+)""",
    """\sSource_File="({src_file_name}[^=]+?)\s{0,100}"\s{0,100}\w+=""",
  ]

```