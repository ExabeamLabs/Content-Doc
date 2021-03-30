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
    """\d\d:\d\d:\d\d\s*({host}[^\s]+)\s*Agent_Local_Time="+({time}[^"]+)""",
    """\sComputer_Name="+(({domain}[^\\]+)?\\?({src_host}[^"]+))""",
    """\sUser_Name="+(({domain}[^\\]+)?\\?({user}[^"]+))""",
    """\sSource_Directory="+({src_file_dir}.+?)\s*"+\s*Source_File=""",
    """\sDestination_Directory="+({file_parent}.+?)\s*"+\s*Destination_File=""",
    """\sDestination_File="+({file_name}.+?)\s*"+\s*Operation=""",
    """\sOperation="+({event_code}[^"]+)""",
    """\sApplication="+({process_name}[^"]+)""",
    """\sSource_File="+({src_file_name}.+?)\s*"+\s*Destination""",
  ]

```