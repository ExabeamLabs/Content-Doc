#### Parser Content
```Java
{
Name = leef-digitalguardian-file-read-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Read|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-3
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Write|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-4
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Rename|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-delete
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Recycle|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-5
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Save As|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-read-2
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Open|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-upload
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Network Transfer Upload|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-download
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Network Transfer Download|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-download-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|2|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-upload-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|3|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-6
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|5|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-7
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|7|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-8
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|11|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-9
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|12|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-write-10
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|18|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-delete-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|17|""" ]
}

${DGParserTemplates.leef-digitalguardian-file-operation} {
  Name = leef-digitalguardian-file-read-3
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|21|""" ]
}

{
  Name = leef-digitalguardian-process-created
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Application Start|""" ]
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+) LEEF:""",
    """accountName=(({domain}[^\\]+)\\+)?({user}[^\\\s]+?)\s*(\w+=|$)""",
    """IdentHostName=([^\\]+\\+)?({dest_host}[\w\-.]+?)\s*(\w+=|$)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """SourceDirectory=({directory}.+?)\s*(\w+=|$)""",
    """SourceFile=({process_name}.+?)\s*(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```