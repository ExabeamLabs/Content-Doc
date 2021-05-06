#### Parser Content
```Java
{
Name = cef-defender-atp-process
  DataType = "process-created"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceProcessEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """ProcessId":({pid}\d+)""",
     """InitiatingProcessFileName":\s*"({parent_process}[^"]+)""",
     """"FileName":\s*"({process_name}[^"]+)""",
     """DeviceName":\s*"({dest_host}[^"]+)""",
     """ProcessCommandLine":\s*"({command_line}[^"]+)\s*""""
     """MD5":"({md5}[^"]+)""",
 ]
}
```