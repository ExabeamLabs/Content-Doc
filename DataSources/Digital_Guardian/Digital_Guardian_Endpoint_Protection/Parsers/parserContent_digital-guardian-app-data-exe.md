#### Parser Content
```Java
{
Name = digital-guardian-app-data-exe
  Product = Digital Guardian Endpoint Protection
  DataType = "app-activity"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="21"""" ]
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
    """\w+\s\d\d\s\d\d:\d\d:\d\d\s{0,100}({host}[\w\-.]{1,2000})\s\w+=""",
    """\sComputer_Name="(({domain}[^\\]{1,2000})?\\?({src_host}[^"]{1,2000}))""",
    """\sUser_Name="(({domain}[^\\]{1,2000})?\\?({user}[^"]{1,2000}))""",
    """\sSource_Directory="({src_file_dir}[^=]{1,2000}?)\s{0,100}"\s{0,100}\w+=""",
    """\sDestination_Directory="({file_parent}[^=]{1,2000}?)\s{0,100}"\s{0,100}\w+=""",
    """\sDestination_File="({file_name}[^=]{1,2000}?)\s{0,100}"\s{0,100}\w+=""",
    """\sOperation="({event_code}\d{1,100})""",
    """\sApplication="({process_name}[^"]{1,2000})""",
    """\sSource_File="({src_file_name}[^=]{1,2000}?)\s{0,100}"\s{0,100}\w+=""",
  ]

```