#### Parser Content
```Java
{
Name = cef-defender-atp-file
  DataType = "file-operations"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceFileEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """"FolderPath"{1,20}:\s{0,100}"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
     """DeviceName"{1,20}:\s{0,100}"{1,20}({dest_host}({host}[^"\.]{1,2000})?[^"]{1,2000})""",
     """MD5"{1,20}:"{1,20}({md5}[^"]{1,2000})""",
     """"SHA1"{1,20}:(null|"{1,20}({sha1}[^",]{1,2000})"{1,20}),""",
     """"SHA256"{1,20}:(null|"{1,20}({sha256}[^",]{1,2000})"{1,20}),"""
]
}
```