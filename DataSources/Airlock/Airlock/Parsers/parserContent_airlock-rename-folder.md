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
AirlockEvent = {
    Vendor = Airlock
    Product = Airlock
    Lms = Splunk
    TimeFormat = "M/d/yy h:mm:ss a"
    Fields = [
      """\sstart_time="({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
      """\sseverity="({alert_severity}[^"]+)"""",
      """\ssystem_name="({host}[^"]+)"""",
      """\ssession_id="({session_id}[^"]+)"""",
      """\sremote_port="({src_port}[^"]+)"""",
      """\sremote_ip="({src_ip}[^"]+)"""",
      """\sremarks="({activity}[^"]+)"""",
      """\slocal_port="({dest_port}[^"]+)"""",
      """\slocal_ip="({dest_ip}[^"]+)"""",
      """\sevent_type="({event_name}[^"]+)"""",
      """\sevent_id="({event_code}[^"]+)"""",
      """\scommand="({action}[^"]+)"""",
      """\suser_name="(unknown|({user}[^"]+))"""",
      """\sdomain="(Default|({domain}[^"]+))"""",
      """\sfile_size="({bytes}[^"]+)"""",
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))"""
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+(\.({file_ext}[^\\\/\.;"]+))))""" 
    ]

```