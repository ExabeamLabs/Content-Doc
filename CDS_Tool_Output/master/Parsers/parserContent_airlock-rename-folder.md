#### Parser Content
```Java
{
Name = airlock-rename-folder
  DataType = "file-operations"
  Conditions = [ """ Audit Log [""", """ event_type="""", """" time_taken="""", """" system_name="""", """"Rename Folder Successful"""" ]
  Fields = ${AirlockTemplates.AirlockEvent.Fields}[
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+))""",
  ]
}
```