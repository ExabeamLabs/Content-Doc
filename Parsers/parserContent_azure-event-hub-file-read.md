#### Parser Content
```Java
{
Name = azure-event-hub-file-read
  DataType = "file-read"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"ReadProcessMemoryApiCall""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"FolderPath":"({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))""",
    """({accesses}ReadProcessMemoryApiCall)""",
  ]
}
```