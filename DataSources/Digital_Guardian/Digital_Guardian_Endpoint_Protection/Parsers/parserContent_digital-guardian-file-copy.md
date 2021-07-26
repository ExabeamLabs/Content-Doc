#### Parser Content
```Java
{
Name = digital-guardian-file-copy
  Product = Digital Guardian Endpoint Protection
  DataType = "file-write"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="11"""" ]
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
    """\d\d:\d\d:\d\d\s{0,100}({host}[^\s]{1,2000})\s{0,100}Agent_Local_Time="{1,20}({time}[^"]{1,2000})""",
    """\sComputer_Name="{1,20}(({domain}[^\\]{1,2000})?\\?({src_host}[^"]{1,2000}))""",
    """\sUser_Name="{1,20}(({domain}[^\\]{1,2000})?\\?({user}[^"]{1,2000}))""",
    """\sSource_Directory="{1,20}({src_file_dir}.+?)\s{0,100}"{1,20}\s{0,100}Source_File=""",
    """\sDestination_Directory="{1,20}({file_parent}.+?)\s{0,100}"{1,20}\s{0,100}Destination_File=""",
    """\sDestination_File="{1,20}({file_name}.+?)\s{0,100}"{1,20}\s{0,100}Operation=""",
    """\sOperation="{1,20}({event_code}[^"]{1,2000})""",
    """\sApplication="{1,20}({process_name}[^"]{1,2000})""",
    """\sSource_File="{1,20}({src_file_name}.+?)\s{0,100}"{1,20}\s{0,100}Destination""",
  ]

```