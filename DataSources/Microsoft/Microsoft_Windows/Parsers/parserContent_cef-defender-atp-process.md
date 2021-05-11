#### Parser Content
```Java
{
Name = cef-defender-atp-process
  DataType = "process-created"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceProcessEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """ProcessId":({pid}\d{1,100})""",
     """InitiatingProcessFileName":\s{0,100}"({parent_process}[^"]+)""",
     """"FileName":\s{0,100}"({process_name}[^"]+)""",
     """DeviceName":\s{0,100}"({dest_host}[^"]+)""",
     """ProcessCommandLine":\s{0,100}"({command_line}[^"]+)\s{0,100}""""
     """MD5":"({md5}[^"]+)""",
 ]
}
```