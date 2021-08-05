#### Parser Content
```Java
{
Name = cef-defender-atp-process
  DataType = "process-created"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceProcessEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """ProcessId":({pid}\d{1,100})""",
     """InitiatingProcessFileName":\s{0,100}"({parent_process}[^"]{1,2000})""",
     """"FileName":\s{0,100}"({process_name}[^"]{1,2000})""",
     """DeviceName":\s{0,100}"({dest_host}[^"]{1,2000})""",
     """ProcessCommandLine":\s{0,100}"({command_line}[^"]{1,2000})\s{0,100}""""
     """MD5":"({md5}[^"]{1,2000})""",
 ]
}
```