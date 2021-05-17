#### Parser Content
```Java
{
Name = airlock-login-failed
  DataType = "failed-app-login"
  Conditions = [ """ Audit Log [""", """ event_type="""", """" time_taken="""", """" system_name="""", """"Login Failed"""" ]
  Fields = ${AirlockTemplates.AirlockEvent.Fields}[
    """\sremarks="({failure_reason}[^"]{1,2000})"""", 
  ]
}
AirlockEvent = {
    Vendor = Airlock
    Product = Airlock
    Lms = Splunk
    TimeFormat = "M/d/yy h:mm:ss a"
    Fields = [
      """\sstart_time="({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
      """\sseverity="({alert_severity}[^"]{1,2000})"""",
      """\ssystem_name="({host}[^"]{1,2000})"""",
      """\ssession_id="({session_id}[^"]{1,2000})"""",
      """\sremote_port="({src_port}[^"]{1,2000})"""",
      """\sremote_ip="({src_ip}[^"]{1,2000})"""",
      """\sremarks="({activity}[^"]{1,2000})"""",
      """\slocal_port="({dest_port}[^"]{1,2000})"""",
      """\slocal_ip="({dest_ip}[^"]{1,2000})"""",
      """\sevent_type="({event_name}[^"]{1,2000})"""",
      """\sevent_id="({event_code}[^"]{1,2000})"""",
      """\scommand="({action}[^"]{1,2000})"""",
      """\suser_name="(unknown|({user}[^"]{1,2000}))"""",
      """\sdomain="(Default|({domain}[^"]{1,2000}))"""",
      """\sfile_size="({bytes}[^"]{1,2000})"""",
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}?(\.({file_ext}[^\\\/\.;"]{1,2000}))))"""
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}(\.({file_ext}[^\\\/\.;"]{1,2000}))))""" 
    ]

```