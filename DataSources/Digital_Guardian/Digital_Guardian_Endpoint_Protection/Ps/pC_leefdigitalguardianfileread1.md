#### Parser Content
```Java
{
Name = leef-digitalguardian-file-read-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|File Read|""" ]
}
leef-digitalguardian-file-operation = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000}) LEEF:""",
    """\|Digital Guardian\|([^\|]{0,2000}\|){2}({event_code}[^\|]{1,2000})""",
    """accountName =(({domain}[^\\\s]{1,2000})\s{0,100}\\+)?({user}[^\\\s]{1,2000}?)\s{0,100}(\w+=|$)""",
    """IdentHostName =([^\\]{1,2000}\\+)?({dest_host}[\w\-.]{1,2000}?)\s{0,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Application=({app}.+?)\s{0,100}(\w+=|$)""",
    """srcBytes=({bytes}\d{1,100})""",
    """DestinationDirectory=(|({file_parent}.+?))\s{0,100}(\w+=|$)""",
    """DestinationFile=(|({file_name}.+?(\.({file_ext}[^\.]{1,2000}?))?))\s{0,100}(\w+=|$)""",
    """SourceDirectory=(|({src_file_dir}.+?))\s{0,100}(\w+=|$)""",
    """SourceFile=(|({src_file_name}.+?))\s{0,100}(\w+=|$)""",
  ]}
```